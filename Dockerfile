FROM node:alpine
WORKDIR /usr/app
COPY ./package.json ./
COPY ./package-lock.json ./
RUN npm install
COPY ./controllers ./
COPY ./middlewares ./
COPY ./models ./
COPY ./routers ./
COPY ./utils ./
COPY ./ .env ./
COPY ./index.js ./
CMD ["npm", "start"]





