# Execução alternativa em contêiner (API + frontend servidos pelo Express na porta 3000).
FROM node:20-alpine
WORKDIR /app
COPY backend/package*.json backend/
RUN cd backend && npm ci --omit=dev
COPY backend backend
COPY frontend frontend
RUN mkdir /data && chown -R node:node /data /app
ENV HOST=0.0.0.0 PORT=3000 DATA_FILE=/data/data.json
EXPOSE 3000
USER node
WORKDIR /app/backend
CMD ["node", "server.js"]
