
# About

This web-app is an Assignment submission web portal.


## Tech Stack
Backend : NodeJS/Express
Database: MongoDB
Libraries: JWT for auth and Zod for input validation.
## Project Setup Steps

1. Clone the repo locally. Then in the root of the folder where package.json lies, run the following command.

```bash
npm install
```

This will install all necessary dependencies needed to run the project locally.

2. Then create a .env file in the root of the folder. Add the following keys in the file.

```
MONGO_URL=
JWT_SECRET=
ADMIN_SECRET=
PORT=3000
```

Give a JWT_SECRET and ADMIN_SECRET as per your own choice.
Also, add the MongoDB URL.

## Features
1. Users can upload assignments.
2. Admins can accept or reject these assignments.
3. Admins can see all the assignments submitted to them.
4. Admins can see the user name and task done.

## Start the App 
In the VS code terminal, run the command: ```npm run dev``` to start the project. If everything is set up properly, then the app will start and you will see this in the console. 

```
[nodemon] starting `node index.js`
Server is listening on port 3000
MongoDB connected
```



## API endpoints

Go to the given URL to access the API documentation.
```
https://documenter.getpostman.com/view/17849933/2sAXxQeCAB
```

