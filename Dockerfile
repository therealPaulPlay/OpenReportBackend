# Environment Image
FROM node:22-alpine

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./

RUN npm install

# Bundle app source
COPY . .

# This is purely informational! Change it to the port you are using for good measure
EXPOSE 3008

# Run the node command with server.js to start it
CMD [ "node", "server.js" ]