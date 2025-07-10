{
  "name": "cricketbet-backend",
  "version": "1.0.0",
  "description": "CricketBet Backend with Real Cricket Data Integration",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "migrate": "node migrate.js"
  },
  "keywords": [
    "cricket",
    "betting",
    "express",
    "postgresql",
    "real-time"
  ],
  "author": "CricketBet Team",
  "license": "MIT",
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cloudinary": "^1.41.0",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.2",
    "multer": "^1.4.5-lts.1",
    "node-cron": "^3.0.2",
    "node-fetch": "^2.7.0",
    "pg": "^8.11.3",
    "sqlite3": "^5.1.7"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
