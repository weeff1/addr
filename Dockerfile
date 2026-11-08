FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY server.js ./
COPY index.html ./
ENV PORT=8000
ENV HOST=0.0.0.0
EXPOSE 8000
CMD ["node", "server.js"]
