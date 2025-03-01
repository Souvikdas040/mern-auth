# MERN Authentication System

A full authentication system built using the MERN stack (MongoDB, Express.js, React, and Node.js) with features like JWT authentication, email verification, and password reset.

## Features

- User Registration & Login with JWT Authentication
- Email Verification via Token
- Password Reset with Email Link
- Protected Routes for Authorized Users
- Secure Password Hashing with bcrypt
- MongoDB Database with Mongoose

## Tech Stack

- **Frontend:** React, Axios, React Router
- **Backend:** Node.js, Express.js, JWT, bcrypt
- **Database:** MongoDB, Mongoose
- **Email Service:** Nodemailer (Gmail, SMTP)

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/Souvikdas040/mern-auth.git
   cd mern-auth
   ```

2. **Install dependencies for backend:**
   ```sh
   cd server
   npm install
   ```

3. **Install dependencies for frontend:**
   ```sh
   cd ../client
   npm install
   ```

4. **Set up environment variables:**
   - Create a `.env` file in the backend directory and add:
     ```env
     MONGO_URI=your_mongodb_connection_string
     JWT_SECRET=your_jwt_secret
     NODE_ENV='your_node_env'
     
     SMTP_USER=your_app_email
     SMTP_PASSWORD=your_app_password
     SENDER_EMAIL="your_email"
     ```

5. **Run the backend server:**
   ```sh
   cd server
   npm run server
   ```

6. **Run the frontend server:**
   ```sh
   cd client
   npm run dev
   ```

## API Routes

### Auth Routes
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login and receive JWT token
- `POST /api/auth/logout` - Getting logged out
- `POST /api/auth/send-verify-otp` - Sends an OTP to verify registered email
- `POST /api/auth/verify-account` - Email verification
- `GET /api/auth/is-auth` - Email verification
- `POST /api/auth/send-reset-otp` - Send password reset OTP to the registered email
- `POST /api/auth/reset-password` - Reset password

## Folder Structure
```
mern-auth-system/
│── server/
│   ├── models/
│   ├── routes/
│   ├── controllers/
│   ├── middleware/
│   ├── config/
│   ├── server.js
│
│── client/
│   ├── src/
│       ├── assets/
│       ├── components/
│       ├── pages/
│       ├── context/
│       ├── App.js
│
│── README.md
```

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.

## License
MIT
