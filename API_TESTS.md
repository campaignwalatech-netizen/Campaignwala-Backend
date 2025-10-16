# API Test Examples

This file contains example requests for all API endpoints. You can use tools like Postman, Insomnia, or curl to test these endpoints.

## Base URL

```
http://localhost:5000/api
```

## 1. Health Check

### Server Status

```bash
curl -X GET http://localhost:5000/
```

### API Health Check

```bash
curl -X GET http://localhost:5000/api/health
```

## 2. Authentication Endpoints

### Send OTP

```bash
curl -X POST http://localhost:5000/api/users/send-otp \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "9876543210"
  }'
```

### Register User

```bash
curl -X POST http://localhost:5000/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "9876543210",
    "password": "password123",
    "otp": "112233"
  }'
```

### Login User

```bash
curl -X POST http://localhost:5000/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "9876543210",
    "password": "password123"
  }'
```

### Verify OTP

```bash
curl -X POST http://localhost:5000/api/users/verify-otp \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "9876543210",
    "otp": "112233"
  }'
```

## 3. User Profile Endpoints (Require Authentication)

### Get Profile

```bash
curl -X GET http://localhost:5000/api/users/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Update Profile

```bash
curl -X PUT http://localhost:5000/api/users/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "password": "newpassword123"
  }'
```

### Change Password

```bash
curl -X PUT http://localhost:5000/api/users/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "currentPassword": "password123",
    "newPassword": "newpassword123"
  }'
```

## 4. Admin Endpoints (Require Admin Role)

### Get All Users

```bash
curl -X GET "http://localhost:5000/api/users/admin/users?page=1&limit=10" \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"
```

### Get All Users with Filters

```bash
curl -X GET "http://localhost:5000/api/users/admin/users?page=1&limit=5&role=user&isVerified=true&search=987" \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"
```

### Get User by ID

```bash
curl -X GET http://localhost:5000/api/users/admin/users/USER_ID \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"
```

### Update User Role

```bash
curl -X PUT http://localhost:5000/api/users/admin/users/USER_ID/role \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN" \
  -d '{
    "role": "admin"
  }'
```

### Toggle User Status

```bash
curl -X PUT http://localhost:5000/api/users/admin/users/USER_ID/toggle-status \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"
```

### Delete User

```bash
curl -X DELETE http://localhost:5000/api/users/admin/users/USER_ID \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"
```

### Get Dashboard Stats

```bash
curl -X GET http://localhost:5000/api/users/admin/dashboard-stats \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"
```

## 5. Creating Admin User

To create an admin user, first register a normal user and then manually update the role in MongoDB:

```javascript
// Connect to MongoDB
use campaignwala_panels

// Update user role to admin
db.users.updateOne(
  { phoneNumber: "9876543210" },
  { $set: { role: "admin" } }
)
```

Or you can modify the register controller temporarily to create admin users.

## 6. Complete Testing Flow

### Step 1: Register a new user

```bash
# Send OTP
curl -X POST http://localhost:5000/api/users/send-otp \
  -H "Content-Type: application/json" \
  -d '{"phoneNumber": "9876543210"}'

# Register with OTP
curl -X POST http://localhost:5000/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "9876543210",
    "password": "password123",
    "otp": "112233"
  }'
```

### Step 2: Login and get token

```bash
curl -X POST http://localhost:5000/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "9876543210",
    "password": "password123"
  }'
```

### Step 3: Use the token for authenticated requests

```bash
# Replace YOUR_JWT_TOKEN with the token received from login
curl -X GET http://localhost:5000/api/users/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Step 4: Create admin user and test admin endpoints

```bash
# After making user admin in database
curl -X GET http://localhost:5000/api/users/admin/dashboard-stats \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"
```

## 7. Error Testing

### Invalid OTP

```bash
curl -X POST http://localhost:5000/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "9876543210",
    "password": "password123",
    "otp": "000000"
  }'
```

### Invalid Credentials

```bash
curl -X POST http://localhost:5000/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "9876543210",
    "password": "wrongpassword"
  }'
```

### Unauthorized Access

```bash
curl -X GET http://localhost:5000/api/users/profile
```

### Non-admin trying admin endpoints

```bash
curl -X GET http://localhost:5000/api/users/admin/users \
  -H "Authorization: Bearer USER_JWT_TOKEN"
```

## 8. Postman Collection

You can import these requests into Postman by creating a new collection and adding these requests. Make sure to:

1. Set up environment variables for:

   - `baseUrl`: `http://localhost:5000/api`
   - `userToken`: JWT token for regular user
   - `adminToken`: JWT token for admin user

2. Use `{{baseUrl}}` in your requests
3. Set Authorization header to `Bearer {{userToken}}` or `Bearer {{adminToken}}`

## 9. Response Examples

### Successful Registration Response

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

### Error Response

```json
{
  "success": false,
  "message": "Invalid OTP"
}
```
