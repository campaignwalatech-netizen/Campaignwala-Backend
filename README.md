# Campaignwala Panels Backend

Complete Node.js backend API for user authentication and management with admin panel functionality.

## Features

- 🔐 User Authentication (Register/Login)
- 📱 Phone Number Verification with OTP
- 👥 Role-based Access Control (User/Admin)
- 🔑 JWT Token Authentication
- 📊 Admin Dashboard with User Management
- 📖 Complete Swagger API Documentation
- 🛡️ Password Hashing with bcrypt
- 📋 Input Validation & Error Handling

## Tech Stack

- **Backend**: Node.js, Express.js
- **Database**: MongoDB with Mongoose
- **Authentication**: JWT (JSON Web Tokens)
- **Password Hashing**: bcryptjs
- **Documentation**: Swagger/OpenAPI 3.0
- **Environment**: dotenv

## Installation

1. Clone the repository:

```bash
git clone https://github.com/campaignwalatech-netizen/campaignwala-panels-backend.git
cd campaignwala-panels-backend
```

2. Install dependencies:

```bash
npm install
```

3. Set up environment variables:
   Create a `.env` file in the root directory:

```env
NODE_ENV=development
PORT=5000
MONGODB_URI=mongodb://localhost:27017/campaignwala_panels
JWT_SECRET=your_super_secret_jwt_key_here_change_in_production
JWT_EXPIRE=7d
STATIC_OTP=112233
```

4. Start MongoDB service on your system

5. Run the application:

```bash
# Development mode with nodemon
npm run dev

# Production mode
npm start
```

The server will start on `http://localhost:5000`

## API Documentation

Access the complete Swagger documentation at: `http://localhost:5000/api-docs`

## API Endpoints

### Base URL: `http://localhost:5000/api`

### Authentication Endpoints

| Method | Endpoint            | Description                  | Auth Required |
| ------ | ------------------- | ---------------------------- | ------------- |
| `POST` | `/users/send-otp`   | Send OTP to phone number     | No            |
| `POST` | `/users/register`   | Register new user            | No            |
| `POST` | `/users/login`      | User login                   | No            |
| `POST` | `/users/verify-otp` | Verify phone number with OTP | No            |

### User Profile Endpoints

| Method | Endpoint                 | Description              | Auth Required |
| ------ | ------------------------ | ------------------------ | ------------- |
| `GET`  | `/users/profile`         | Get current user profile | Yes           |
| `PUT`  | `/users/profile`         | Update user profile      | Yes           |
| `PUT`  | `/users/change-password` | Change user password     | Yes           |

### Admin Endpoints

| Method   | Endpoint                                   | Description                   | Auth Required | Admin Only |
| -------- | ------------------------------------------ | ----------------------------- | ------------- | ---------- |
| `GET`    | `/users/admin/users`                       | Get all users with pagination | Yes           | Yes        |
| `GET`    | `/users/admin/users/:userId`               | Get user by ID                | Yes           | Yes        |
| `PUT`    | `/users/admin/users/:userId/role`          | Update user role              | Yes           | Yes        |
| `PUT`    | `/users/admin/users/:userId/toggle-status` | Toggle user active status     | Yes           | Yes        |
| `DELETE` | `/users/admin/users/:userId`               | Delete user                   | Yes           | Yes        |
| `GET`    | `/users/admin/dashboard-stats`             | Get dashboard statistics      | Yes           | Yes        |

### Health Check

| Method | Endpoint  | Description      | Auth Required |
| ------ | --------- | ---------------- | ------------- |
| `GET`  | `/health` | API health check | No            |
| `GET`  | `/`       | Server status    | No            |

## Authentication

### JWT Token

All protected endpoints require a JWT token in the Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

### User Roles

- **user**: Regular user with basic access
- **admin**: Administrative user with full access to user management

## Request/Response Examples

### 1. Send OTP

**Request:**

```http
POST /api/users/send-otp
Content-Type: application/json

{
  "phoneNumber": "9876543210"
}
```

**Response:**

```json
{
  "success": true,
  "message": "OTP sent successfully",
  "data": {
    "phoneNumber": "9876543210",
    "otp": "112233"
  }
}
```

### 2. Register User

**Request:**

```http
POST /api/users/register
Content-Type: application/json

{
  "phoneNumber": "9876543210",
  "password": "password123",
  "otp": "112233"
}
```

**Response:**

```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "_id": "64a1b2c3d4e5f6789abcdef0",
      "phoneNumber": "9876543210",
      "role": "user",
      "isVerified": true,
      "isActive": true,
      "createdAt": "2024-01-15T10:30:00.000Z",
      "updatedAt": "2024-01-15T10:30:00.000Z"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

### 3. Login

**Request:**

```http
POST /api/users/login
Content-Type: application/json

{
  "phoneNumber": "9876543210",
  "password": "password123"
}
```

**Response:**

```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "_id": "64a1b2c3d4e5f6789abcdef0",
      "phoneNumber": "9876543210",
      "role": "user",
      "isVerified": true,
      "isActive": true,
      "createdAt": "2024-01-15T10:30:00.000Z",
      "updatedAt": "2024-01-15T10:30:00.000Z"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

### 4. Get All Users (Admin)

**Request:**

```http
GET /api/users/admin/users?page=1&limit=10&role=user
Authorization: Bearer <admin_jwt_token>
```

**Response:**

```json
{
  "success": true,
  "message": "Users retrieved successfully",
  "data": {
    "users": [
      {
        "_id": "64a1b2c3d4e5f6789abcdef0",
        "phoneNumber": "9876543210",
        "role": "user",
        "isVerified": true,
        "isActive": true,
        "createdAt": "2024-01-15T10:30:00.000Z",
        "updatedAt": "2024-01-15T10:30:00.000Z"
      }
    ],
    "pagination": {
      "current": 1,
      "pages": 1,
      "total": 1
    }
  }
}
```

### 5. Dashboard Stats (Admin)

**Request:**

```http
GET /api/users/admin/dashboard-stats
Authorization: Bearer <admin_jwt_token>
```

**Response:**

```json
{
  "success": true,
  "message": "Dashboard stats retrieved successfully",
  "data": {
    "totalUsers": 150,
    "verifiedUsers": 120,
    "adminUsers": 5,
    "activeUsers": 145,
    "recentRegistrations": 25,
    "unverifiedUsers": 30,
    "inactiveUsers": 5
  }
}
```

## Error Responses

All error responses follow this format:

```json
{
  "success": false,
  "message": "Error description",
  "error": "Additional error details (development only)"
}
```

### Common Status Codes

- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `429` - Too Many Requests
- `500` - Internal Server Error

## Database Schema

### User Model

```javascript
{
  phoneNumber: String (required, unique, 10 digits),
  password: String (required, hashed),
  role: String (enum: ['user', 'admin'], default: 'user'),
  isVerified: Boolean (default: false),
  isActive: Boolean (default: true),
  otpAttempts: Number (default: 0),
  lastOtpSent: Date,
  createdAt: Date,
  updatedAt: Date
}
```

## Security Features

- Password hashing with bcrypt (salt rounds: 12)
- JWT token authentication
- Rate limiting for OTP requests (5 attempts per hour)
- Input validation and sanitization
- Role-based access control
- Secure password requirements (minimum 6 characters)

## Development

### Project Structure

```
campaignwala-panels-backend/
├── src/
│   ├── config/
│   │   ├── db.js              # Database connection
│   │   └── swagger.js         # Swagger configuration
│   ├── middleware/
│   │   └── user.middleware.js # Authentication middleware
│   ├── modules/
│   │   └── users/
│   │       ├── user.model.js    # User model
│   │       ├── user.controller.js # User controllers
│   │       └── user.router.js   # User routes
│   └── router/
│       └── index.js           # Main router
├── .env                       # Environment variables
├── index.js                   # Entry point
├── package.json              # Dependencies
└── README.md                 # Documentation
```

### Adding New Features

1. Create new model in `src/modules/[feature]/`
2. Implement controller functions
3. Add routes with Swagger documentation
4. Update main router in `src/router/index.js`
5. Add middleware if needed

## Environment Variables

| Variable      | Description                | Default                                       |
| ------------- | -------------------------- | --------------------------------------------- |
| `NODE_ENV`    | Environment mode           | development                                   |
| `PORT`        | Server port                | 5000                                          |
| `MONGODB_URI` | MongoDB connection string  | mongodb://localhost:27017/campaignwala_panels |
| `JWT_SECRET`  | JWT signing secret         | (required)                                    |
| `JWT_EXPIRE`  | JWT expiration time        | 7d                                            |
| `STATIC_OTP`  | Static OTP for development | 112233                                        |

## Production Deployment

1. Set `NODE_ENV=production`
2. Use strong `JWT_SECRET`
3. Configure production MongoDB URI
4. Integrate real SMS service for OTP
5. Remove static OTP from responses
6. Set up proper logging
7. Configure reverse proxy (nginx)
8. Enable HTTPS

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Update documentation
6. Submit a pull request

## License

This project is licensed under the ISC License.

## Support

For support and queries, contact: support@campaignwala.com
