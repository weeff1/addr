'use strict';
/* ============================================================
 * 聊天站 · 手机版服务端（零依赖）
 * ------------------------------------------------------------
 *  特点：
 *   - 只用 Node 内置模块，不需要 npm install、不需要编译任何东西
 *   - 实时性用「客户端每 2 秒轮询一次」实现（不依赖 WebSocket）
 *   - 消息存本地 JSON 文件（data/chat-db.json），不用数据库
 *   - 同时把 index.html 一起托管出去（浏览器打开地址即可用）
 *
 *  启动：node server.js
 *  默认端口 3000，监听 0.0.0.0（同 WiFi 的其它设备也能连）
 *  改端口：PORT=8080 node server.js
 * ============================================================ */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

/* ============================ 配置 ============================ */
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'chat-db.json');

const MAX_BODY = 64 * 1024;          // 请求体上限
const MAX_TEXT_LEN = 2000;           // 单条消息上限
const AVATAR_MAX_CHARS = 40 * 1024;  // 头像（压缩后的 data URL）长度上限
const HISTORY_DEFAULT = 100;
const HISTORY_MAX = 200;
const MAX_STORED_MESSAGES = 5000;    // 文件里最多留多少条，超了丢最旧的
const MAX_RECALLS = 600;             // 撤销记录最多留多少条

const TOKEN_TTL_MS = Number(process.env.TOKEN_TTL_DAYS || 30) * 24 * 3600 * 1000;
const TOKEN_MAX_PER_USER = 5;
const ONLINE_WINDOW_MS = 45000;      // 45 秒内轮询过就算在线

const LOGIN_MAX_FAILS = 10;
const LOGIN_WINDOW_MS = 5 * 60 * 1000;
const REGISTER_MAX = 20;
const REGISTER_WINDOW_MS = 60 * 60 * 1000;

/* ============================ 存储（JSON 文件） ============================ */
let db = {
  users: [],       // { id, account, salt, hash, createdAt }
  messages: [],    // { id, userId, account, text, clientId, createdAt }
  sessions: [],    // { token, userId, createdAt, expiresAt }
  recalls: [],     // { seq, messageId, by, at }
  meta: { seq: 0, nextUserId: 1, nextMessageId: 1 }
};

function ensureDataDir() {
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}
}

function loadDb() {
  ensureDataDir();
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    db.users = Array.isArray(parsed.users) ? parsed.users : [];
    db.messages = Array.isArray(parsed.messages) ? parsed.messages : [];
    db.sessions = Array.isArray(parsed.sessions) ? parsed.sessions : [];
    db.recalls = Array.isArray(parsed.recalls) ? parsed.recalls : [];
    const m = parsed.meta || {};
    db.meta = {
      seq: Number(m.seq) || 0,
      nextUserId: Number(m.nextUserId) || (maxId(db.users, 'id') + 1),
      nextMessageId: Number(m.nextMessageId) || (maxId(db.messages, 'id') + 1)
    };
  } catch (e) {
    if (e.code !== 'ENOENT') console.warn('[db] 读取失败，将新建：', e.message);
  }
}

function maxId(list, key) {
  let n = 0;
  for (const it of list) if (Number(it[key]) > n) n = Number(it[key]);
  return n;
}

/** 原子写盘：先写 .tmp 再 rename，避免写到一半断电把库写坏 */
function saveDb() {
  ensureDataDir();
  const tmp = DB_FILE + '.tmp';
  try {
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DB_FILE);
  } catch (e) {
    console.warn('[db] 保存失败：', e.message);
  }
}

function trimMessages() {
  if (db.messages.length > MAX_STORED_MESSAGES) {
    db.messages = db.messages.slice(db.messages.length - MAX_STORED_MESSAGES);
  }
  if (db.recalls.length > MAX_RECALLS) {
    db.recalls = db.recalls.slice(db.recalls.length - MAX_RECALLS);
  }
}

/* ============================ 校验 ============================ */
function normalizeAccount(raw) {
  return typeof raw === 'string' ? raw.trim() : '';
}

const RESERVED_ACCOUNTS = ['全体成员'];   // 保留名，防止有人注册它来冒充群发

function validateAccount(account) {
  if (!account) return '请输入账号';
  if (RESERVED_ACCOUNTS.indexOf(account) >= 0) return '这个账号名被系统保留，换一个';
  if (Array.from(account).length > 16) return '账号最多 16 个字符';
  if (/\s/.test(account)) return '账号不能包含空格';
  if (/[\u0000-\u001f\u007f]/.test(account)) return '账号包含非法字符';
  return null;
}

/** 密码规则：字母或数字，6-20 位 */
function validatePassword(password) {
  if (typeof password !== 'string' || password.length === 0) return '请输入密码';
  if (!/^[A-Za-z0-9]+$/.test(password)) return '密码只能使用字母或数字';
  if (password.length < 6) return '密码至少 6 位';
  if (password.length > 20) return '密码最多 20 位';
  return null;
}

function normalizeText(raw) {
  return typeof raw === 'string' ? raw.replace(/\r\n/g, '\n').trim() : '';
}

/* ============================ 密码哈希 ============================ */
function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const key = await scryptAsync(password, salt);
  return { salt, hash: key.toString('hex') };
}

async function verifyPassword(password, salt, hash) {
  try {
    const key = await scryptAsync(password, salt);
    const stored = Buffer.from(hash, 'hex');
    if (stored.length !== key.length) return false;
    return crypto.timingSafeEqual(key, stored);
  } catch (e) { return false; }
}

/* ============================ 用户 / 会话 ============================ */
function findUserByAccount(account) {
  return db.users.find(u => u.account === account) || null;
}
function findUserById(id) {
  return db.users.find(u => u.id === id) || null;
}

function createSession(userId) {
  const now = Date.now();
  const mine = db.sessions.filter(s => s.userId === userId);
  if (mine.length >= TOKEN_MAX_PER_USER) {
    const drop = mine.slice(0, mine.length - TOKEN_MAX_PER_USER + 1).map(s => s.token);
    db.sessions = db.sessions.filter(s => !drop.includes(s.token));
  }
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions.push({ token, userId, createdAt: now, expiresAt: now + TOKEN_TTL_MS });
  return token;
}

function userByToken(token) {
  if (!token) return null;
  const s = db.sessions.find(x => x.token === token);
  if (!s) return null;
  if (!s.expiresAt || s.expiresAt <= Date.now()) {
    db.sessions = db.sessions.filter(x => x.token !== token);
    saveDb();
    return null;
  }
  return findUserById(s.userId);
}

function tokenFromRequest(req) {
  const auth = req.headers['authorization'];
  if (!auth || !/^Bearer\s+/i.test(auth)) return '';
  return auth.replace(/^Bearer\s+/i, '').trim();
}

function sweepSessions() {
  const now = Date.now();
  const before = db.sessions.length;
  db.sessions = db.sessions.filter(s => s.expiresAt && s.expiresAt > now);
  if (before !== db.sessions.length) saveDb();
}

/* ============================ 在线人数 ============================ */
const presence = new Map(); // userId -> lastPollAt

function touchPresence(userId) { presence.set(userId, Date.now()); }

function onlineCount() {
  const now = Date.now();
  let n = 0;
  for (const [id, ts] of presence) {
    if (now - ts < ONLINE_WINDOW_MS) n++;
    else presence.delete(id);
  }
  return n;
}

/* ============================ 限流 ============================ */
const buckets = new Map(); // key -> { count, resetAt }

function hitLimit(key, max, windowMs) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now >= b.resetAt) { b = { count: 0, resetAt: now + windowMs }; buckets.set(key, b); }
  b.count += 1;
  if (buckets.size > 2000) {
    for (const [k, v] of buckets) if (now >= v.resetAt) buckets.delete(k);
  }
  return b.count <= max;
}

/* ============================ 消息 ============================ */
function toDto(m) {
  const dto = { id: m.id, account: m.account, text: m.text, createdAt: m.createdAt };
  if (m.clientId) dto.clientId = m.clientId;
  if (m.to) dto.to = m.to;
  if (m.mentions && m.mentions.length) dto.mentions = m.mentions;
  if (m.mentionAll) dto.mentionAll = true;
  return dto;
}

/** 从文本里提取「真的存在」的 @账号（不存在的名字不算，防止冒充） */
function extractMentions(text) {
  const allowed = new Set(db.users.map(u => u.account));
  const out = [];
  String(text).replace(/@([\u4e00-\u9fa5A-Za-z0-9_\-]{1,20})/g, (all, name) => {
    if (allowed.has(name) && out.indexOf(name) < 0) out.push(name);
    return all;
  });
  return out;
}

/** 带 clientId 时按（账号 + clientId）幂等，重复提交返回原消息 */
function saveMessage(user, text, clientId, to) {
  if (clientId) {
    const exist = db.messages.find(m => m.userId === user.id && m.clientId === clientId);
    if (exist) return { message: toDto(exist), duplicate: true };
  }
  const mentions = extractMentions(text);
  /* @全体成员 只有账号名为「原作者」的人才算数，别人手打这串字只是普通文字 */
  const mentionAll = user.account === '原作者' && /@全体成员/.test(text);

  const row = {
    id: db.meta.nextMessageId++,
    userId: user.id,
    account: user.account,
    text,
    clientId: clientId || null,
    createdAt: Date.now()
  };
  if (to) row.to = to;
  if (mentions.length) row.mentions = mentions;
  if (mentionAll) row.mentionAll = true;
  db.messages.push(row);
  trimMessages();
  saveDb();
  return { message: toDto(row), duplicate: false };
}

/** 把某个人加进好友名单（已经存在就不重复加） */
function ensureContact(user, account) {
  if (!user.contacts) user.contacts = [];
  if (account && user.contacts.indexOf(account) < 0) user.contacts.push(account);
}

/** 好友名单（顺手过滤掉已经被删掉的账号） */
function contactList(user) {
  return (user.contacts || [])
    .filter(a => !!findUserByAccount(a))
    .map(a => ({ account: a }));
}

/** 一条消息对某个账号是否可见：公共消息人人可见；私聊只有双方可见 */
function canSee(m, user) {
  if (!m.to) return true;
  return m.userId === user.id || m.to === user.account;
}

function messagesAfter(afterId, limit, user) {
  const list = db.messages.filter(m => m.id > afterId && (!user || canSee(m, user)));
  if (!limit || list.length <= limit) return list.map(toDto);

  // 超出 limit 时：如果列表本来就短于上限（首次进入），给最近 limit 条；
  // 如果是长时间断线后追消息，只给最新的 limit 条，同时把游标推上去。
  return list.slice(list.length - limit).map(toDto);
}

/** to 为空 = 公共聊天室；to = 某个账号 = 我和他的私聊 */
function historyBefore(beforeId, limit, user, to) {
  let list = db.messages.filter(m => (user ? canSee(m, user) : true));
  if (to) {
    list = list.filter(m =>
      (m.userId === user.id && m.to === to) ||
      (m.to === user.account && m.account === to));
  } else {
    list = list.filter(m => !m.to);
  }
  if (beforeId) list = list.filter(m => m.id < beforeId);
  return list.slice(-limit).map(toDto);
}

/* ============================ HTTP 工具 ============================ */
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS'
  });
  res.end(body);
}

function fail(res, code, error) { sendJson(res, code, { ok: false, error }); }

function readBody(req) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { req.destroy(); resolve({ error: '请求内容过大' }); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({ data: {} });
      try { resolve({ data: JSON.parse(raw) }); }
      catch (e) { resolve({ error: '请求格式错误（需要 JSON）' }); }
    });
    req.on('error', () => resolve({ error: '读取请求失败' }));
  });
}

function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

/* ============================ 静态文件 ============================ */
function serveIndex(req, res) {
  const file = path.join(ROOT, 'index.html');
  fs.readFile(file, (err, buf) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('找不到 index.html，请把它和 server.js 放在同一个文件夹');
      return;
    }
    const plain = () => {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': buf.length,
        'Cache-Control': 'no-cache'
      });
      res.end(buf);
    };
    /* 页面有 70KB 左右，走免费隧道时偶发传到一半就断（浏览器只渲染半截）。
       压成 gzip 后只有十几 KB，体积小很多，传不完的概率大幅下降。 */
    if (/gzip/i.test(String(req.headers['accept-encoding'] || ''))) {
      zlib.gzip(buf, (e2, gz) => {
        if (e2) { plain(); return; }
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Encoding': 'gzip',
          'Content-Length': gz.length,
          'Cache-Control': 'no-cache',
          'Vary': 'Accept-Encoding'
        });
        res.end(gz);
      });
      return;
    }
    plain();
  });
}

/* ============================ 业务路由 ============================ */
/** 头像：只允许 png/jpeg/webp 的 data URL，且压缩后不超过 40KB */
function validateAvatar(avatar) {
  if (avatar === null || avatar === undefined || avatar === '') return null;   // 不传就是没头像
  if (typeof avatar !== 'string') return '头像格式不对';
  if (avatar.length > AVATAR_MAX_CHARS) return '头像太大，请换一张小一点的';
  if (!/^data:image\/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$/.test(avatar)) return '头像格式不对，只支持图片';
  return null;
}

function handleContacts(req, res, user) {
  return sendJson(res, 200, { ok: true, contacts: contactList(user) });
}

async function handleAddContact(req, res, user) {
  const { data, error } = await readBody(req);
  if (error) return fail(res, 400, error);
  const target = normalizeAccount(data.account || '');
  if (!target) return fail(res, 400, '请输入要加的账号');
  if (target === user.account) return fail(res, 400, '不能加自己');
  const other = findUserByAccount(target);
  if (!other) return fail(res, 404, '没有这个账号');
  /* 双向互加：你加了他，他也自动有你 */
  ensureContact(user, other.account);
  ensureContact(other, user.account);
  saveDb();
  return sendJson(res, 200, { ok: true, contacts: contactList(user) });
}

function handleRemoveContact(req, res, user, target) {
  user.contacts = (user.contacts || []).filter(a => a !== target);
  saveDb();
  return sendJson(res, 200, { ok: true, contacts: contactList(user) });
}

/** 所有账号的头像（登录后才能拿，前端缓存起来渲染消息旁的头像） */
function handleAvatars(req, res, user) {
  const avatars = {};
  db.users.forEach(u => { if (u.avatar) avatars[u.account] = u.avatar; });
  return sendJson(res, 200, { ok: true, avatars, myAvatar: user.avatar || null });
}

/** 改自己的头像：随时换，换多少次都行；传 null 表示清掉头像 */
async function handleSetAvatar(req, res, user) {
  if (!hitLimit('avatar:' + user.id, 60, 10 * 60 * 1000)) {
    return fail(res, 429, '换头像太频繁了，歇一会儿再试');
  }
  const { data, error } = await readBody(req);
  if (error) return fail(res, 400, error);

  const avatar = typeof data.avatar === 'string' && data.avatar ? data.avatar : null;
  const err = validateAvatar(avatar);
  if (err) return fail(res, 400, err);

  user.avatar = avatar;
  saveDb();
  return sendJson(res, 200, { ok: true, avatar });
}

async function handleRegister(req, res) {
  const ip = clientIp(req);
  if (!hitLimit('reg:' + ip, REGISTER_MAX, REGISTER_WINDOW_MS)) {
    return fail(res, 429, '注册太频繁，请稍后再试');
  }
  const { data, error } = await readBody(req);
  if (error) return fail(res, 400, error);

  const account = normalizeAccount(data.account);
  const password = typeof data.password === 'string' ? data.password : '';

  const accErr = validateAccount(account);
  if (accErr) return fail(res, 400, accErr);
  const pwdErr = validatePassword(password);
  if (pwdErr) return fail(res, 400, pwdErr);

  const avatar = typeof data.avatar === 'string' && data.avatar ? data.avatar : null;
  const avatarErr = validateAvatar(avatar);
  if (avatarErr) return fail(res, 400, avatarErr);

  if (findUserByAccount(account)) return fail(res, 409, '这个账号已经被注册了');

  const { salt, hash } = await hashPassword(password);
  const user = {
    id: db.meta.nextUserId++,
    account,
    salt,
    hash,
    avatar,
    createdAt: Date.now()
  };
  db.users.push(user);
  const token = createSession(user.id);
  sweepSessions();
  saveDb();

  console.log('[register]', account);
  return sendJson(res, 200, { ok: true, token, account: user.account, avatar: user.avatar || null });
}

async function handleLogin(req, res) {
  const ip = clientIp(req);
  const { data, error } = await readBody(req);
  if (error) return fail(res, 400, error);

  const account = normalizeAccount(data.account);
  const password = typeof data.password === 'string' ? data.password : '';

  const accErr = validateAccount(account);
  if (accErr) return fail(res, 400, accErr);
  const pwdErr = validatePassword(password);
  if (pwdErr) return fail(res, 400, pwdErr);

  if (!hitLimit('login:' + ip, LOGIN_MAX_FAILS, LOGIN_WINDOW_MS)) {
    return fail(res, 429, '密码错误次数太多，请过 5 分钟再试');
  }

  const user = findUserByAccount(account);
  if (!user) return fail(res, 401, '账号或密码不对');
  const ok = await verifyPassword(password, user.salt, user.hash);
  if (!ok) return fail(res, 401, '账号或密码不对');

  const token = createSession(user.id);
  sweepSessions();
  saveDb();
  return sendJson(res, 200, { ok: true, token, account: user.account, avatar: user.avatar || null });
}

function handleMe(req, res, user) {
  return sendJson(res, 200, { ok: true, account: user.account, id: user.id, online: onlineCount() });
}

/** @ 提及面板用的账号列表（只给名字，不给任何密码相关字段） */
function handleUsers(req, res, user) {
  const users = db.users
    .map(u => ({ account: u.account }))
    .slice(-200);
  return sendJson(res, 200, {
    ok: true,
    users,
    /* 只有叫「原作者」的账号才有 @全体成员 的选项 */
    canMentionAll: user.account === '原作者'
  });
}

function handleListMessages(req, res, user, query) {
  const before = Number(query.get('before') || 0);
  const limitRaw = Number(query.get('limit') || HISTORY_DEFAULT);
  const limit = Math.min(Math.max(limitRaw || HISTORY_DEFAULT, 1), HISTORY_MAX);
  const to = (query.get('to') || '').trim();
  if (to && !findUserByAccount(to)) return fail(res, 404, '没有这个账号');
  const list = historyBefore(before, limit, user, to);
  return sendJson(res, 200, { ok: true, messages: list, to: to || null, online: onlineCount() });
}

/** 轮询：客户端带上上次收到的最大消息 id 与上次收到的撤销序号 */
function handlePoll(req, res, user, query) {
  touchPresence(user.id);
  const after = Number(query.get('after') || 0);
  const recallAfter = Number(query.get('recallAfter') || 0);
  const limit = Number(query.get('limit') || HISTORY_DEFAULT);

  /* 不论首屏还是增量，都只给我能看见的（公共 + 我和别人的私聊），
     前端自己按会话分流：正在看的那条 append，别的算未读。
     不能在这里只给公共消息，否则游标还是 0 的人永远收不到私聊。 */
  const messages = after > 0
    ? messagesAfter(after, Math.min(limit, HISTORY_MAX), user)
    : messagesAfter(0, Math.min(limit || HISTORY_DEFAULT, HISTORY_DEFAULT), user);

  const recalls = db.recalls
    .filter(r => r.seq > recallAfter)
    .map(r => ({ seq: r.seq, messageId: r.messageId, by: r.by }));

  const lastId = db.messages.length ? db.messages[db.messages.length - 1].id : 0;
  const lastSeq = db.recalls.length ? db.recalls[db.recalls.length - 1].seq : 0;

  return sendJson(res, 200, {
    ok: true,
    account: user.account,
    online: onlineCount(),
    messages,
    recalls,
    /* 好友列表跟着每次轮询一起下发：别人刚加你为好友时，
       你这边不用重新登录也能立刻看到对方，否则会「明明加了好友却看不见他发的消息」。 */
    contacts: contactList(user),
    lastId,
    lastSeq,
    serverTime: Date.now()
  });
}

async function handleSend(req, res, user) {
  const { data, error } = await readBody(req);
  if (error) return fail(res, 400, error);

  const text = normalizeText(data.text);
  if (!text) return fail(res, 400, '消息不能为空');
  if (Array.from(text).length > MAX_TEXT_LEN) {
    return fail(res, 400, '消息不能超过 ' + MAX_TEXT_LEN + ' 个字符');
  }
  const clientId = typeof data.clientId === 'string' && data.clientId
    ? data.clientId.slice(0, 64) : null;

  let to = null;
  if (typeof data.to === 'string' && data.to.trim()) {
    to = normalizeAccount(data.to);
    if (!to) return fail(res, 400, '私聊对象不对');
    if (to === user.account) return fail(res, 400, '不能给自己发私聊');
    const other = findUserByAccount(to);
    if (!other) return fail(res, 404, '没有这个账号');
    /* 发过消息就算互相加了好友（省掉「同意好友」这一步） */
    ensureContact(user, other.account);
    ensureContact(other, user.account);
  }

  const { message, duplicate } = saveMessage(user, text, clientId, to);
  return sendJson(res, 200, { ok: true, message, duplicate: !!duplicate, online: onlineCount() });
}

function handleLogout(req, res, user) {
  const token = tokenFromRequest(req);
  db.sessions = db.sessions.filter(s => s.token !== token);
  presence.delete(user.id);
  saveDb();
  return sendJson(res, 200, { ok: true });
}

function handleRecall(res, user, messageId) {
  const row = db.messages.find(m => m.id === messageId);
  if (!row) return fail(res, 404, '撤销失败：消息不存在');
  if (row.userId !== user.id) return fail(res, 403, '只能撤销自己发的消息');

  // 真删：直接从存储里移除
  db.messages = db.messages.filter(m => m.id !== messageId);
  db.meta.seq += 1;
  db.recalls.push({ seq: db.meta.seq, messageId, by: user.account, at: Date.now() });
  trimMessages();
  saveDb();
  return sendJson(res, 200, { ok: true, messageId, seq: db.meta.seq });
}

/* ============================ 服务器 ============================ */
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
    const pathname = url.pathname;
    const method = req.method.toUpperCase();

    if (method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Max-Age': '86400'
      });
      return res.end();
    }

    /* ---------- 静态页 ---------- */
    if ((pathname === '/' || pathname === '/index.html') && method === 'GET') {
      return serveIndex(req, res);
    }

    /* ---------- 健康检查 ---------- */
    if (pathname === '/api/health' && method === 'GET') {
      return sendJson(res, 200, {
        ok: true,
        online: onlineCount(),
        messages: db.messages.length,
        users: db.users.length,
        time: Date.now(),
        version: 'mobile-1.0'
      });
    }

    /* ---------- 注册 / 登录（无需 token） ---------- */
    if (pathname === '/api/register' && method === 'POST') return handleRegister(req, res);
    if (pathname === '/api/login' && method === 'POST') return handleLogin(req, res);

    /* ---------- 以下都要登录 ---------- */
    const token = tokenFromRequest(req);
    const user = userByToken(token);
    if (!user) return fail(res, 401, '登录已失效，请重新登录');

    if (pathname === '/api/me' && method === 'GET') return handleMe(req, res, user);
    if (pathname === '/api/users' && method === 'GET') return handleUsers(req, res, user);
    if (pathname === '/api/avatars' && method === 'GET') return handleAvatars(req, res, user);
    if (pathname === '/api/avatar' && (method === 'POST' || method === 'PUT')) return handleSetAvatar(req, res, user);
    if (pathname === '/api/contacts' && method === 'GET') return handleContacts(req, res, user);
    if (pathname === '/api/contacts' && method === 'POST') return handleAddContact(req, res, user);
    if (pathname.indexOf('/api/contacts/') === 0 && method === 'DELETE') {
      return handleRemoveContact(req, res, user, decodeURIComponent(pathname.slice('/api/contacts/'.length)));
    }
    if (pathname === '/api/messages' && method === 'GET') {
      return handleListMessages(req, res, user, url.searchParams);
    }
    if (pathname === '/api/poll' && method === 'GET') {
      return handlePoll(req, res, user, url.searchParams);
    }
    if (pathname === '/api/messages' && method === 'POST') return handleSend(req, res, user);
    if (pathname === '/api/logout' && method === 'POST') return handleLogout(req, res, user);

    const delMatch = pathname.match(/^\/api\/messages\/(\d+)$/);
    if (delMatch && method === 'DELETE') {
      return handleRecall(res, user, Number(delMatch[1]));
    }

    return fail(res, 404, '接口不存在');
  } catch (e) {
    console.error('[error]', e);
    try { fail(res, 500, '服务器内部错误'); } catch (e2) {}
  }
});

/* ============================ 启动 ============================ */
loadDb();
sweepSessions();
setInterval(sweepSessions, 30 * 60 * 1000).unref();

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error('\n[启动失败] 端口 ' + PORT + ' 已经被占用。');
    console.error('  换一个端口启动：PORT=8080 node server.js\n');
  } else {
    console.error('[启动失败]', e.message);
  }
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  const msgCount = db.messages.length;
  console.log('');
  console.log('  聊天站 · 手机版 已启动');
  console.log('  本机访问:  http://localhost:' + PORT);
  console.log('  局域网:    http://<这台手机的IP>:' + PORT + '  （同 WiFi 的人用这个）');
  console.log('  消息文件:  ' + DB_FILE + '（已有 ' + msgCount + ' 条消息）');
  console.log('  提示:      想从外网访问，需要另配一条穿透（端口填 ' + PORT + '）');
  console.log('  停止:      在这个窗口按 Ctrl+C');
  console.log('');
});

process.on('SIGINT', () => {
  console.log('\n[退出] 正在保存数据…');
  saveDb();
  process.exit(0);
});
process.on('SIGTERM', () => {
  saveDb();
  process.exit(0);
});
