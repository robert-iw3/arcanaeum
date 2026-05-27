FROM node:24
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
COPY certs/server.crt certs/server.key ./certs/
CMD ["node", "server.js"]