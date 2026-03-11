FROM node:18

# Crear directorio de la app
WORKDIR /usr/src/app

# Instalar dependencias
COPY package*.json ./
RUN npm install

# Copiar el código de la app
COPY . .

# Exponer el puerto que usa el server.js
EXPOSE 3000

# Comando para arrancar la app
CMD [ "npm", "start" ]
