FROM node:24-alpine

WORKDIR /app
COPY package.json ./
COPY public ./public
COPY src ./src

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000
EXPOSE 3000

USER node
CMD ["npm", "start"]
