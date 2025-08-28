# Authentication Service

The Authentication Service handles user registration, login, token management, and security for the HoodMe application.

## Features

- ✅ **User Registration** - Email/phone registration with OTP verification
- ✅ **JWT Authentication** - Access and refresh token management
- ✅ **Login/Logout** - Secure authentication with device tracking
- ✅ **OTP Verification** - Phone/email verification system
- ✅ **Rate Limiting** - Protection against brute force attacks
- ✅ **Security Middleware** - Comprehensive security guards and decorators
- ⏳ **Role-Based Access Control** - User roles and permissions (planned)
- ⏳ **Password Reset** - Secure password recovery (planned)

## API Endpoints

### Public Endpoints (No Authentication Required)

#### POST /auth/register
Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "phoneNumber": "+2348123456789",
  "firstName": "John",
  "lastName": "Doe",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "message": "Registration successful. Please verify your account.",
  "userId": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

#### POST /auth/verify-otp
Verify OTP code sent during registration.

**Request Body:**
```json
{
  "userId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "otpCode": "123456",
  "purpose": "registration"
}
```

#### POST /auth/login
Login with email/phone and password.

**Request Body:**
```json
{
  "login": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "firstName": "John",
    "lastName": "Doe",
    "email": "user@example.com",
    "phoneNumber": "+2348123456789",
    "isVerified": true
  }
}
```

#### POST /auth/refresh
Refresh access token using refresh token.

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### GET /auth/health
Health check endpoint.

### Protected Endpoints (Require Authentication)

#### GET /auth/profile
Get current user profile.

**Headers:**
```
Authorization: Bearer <access_token>
```

#### POST /auth/logout
Logout user and invalidate tokens.

## Security Features

### Rate Limiting
- 10 requests per minute per IP address
- Protects against brute force attacks

### JWT Strategy
- Access tokens expire in 15 minutes
- Refresh tokens expire in 30 days
- Secure token validation with user verification

### Password Security
- Minimum 8 characters
- Must include uppercase, lowercase, number, and special character
- Bcrypt hashing with 12 salt rounds

### OTP Verification
- 6-digit codes
- 10-minute expiration
- One-time use only

### Device Tracking
- Tracks device information for sessions
- IP address and user agent logging
- Multiple device support

## Environment Variables

```env
# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=30d

# Security
BCRYPT_SALT_ROUNDS=12

# Database (from DatabaseModule)
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USERNAME=HoodMe_user
DATABASE_PASSWORD=HoodMe_password
DATABASE_NAME=HoodMe_dev
```

## Usage Examples

### Start Service
```bash
npm run start:auth
```

### Running Tests
```bash
npm test -- --testPathPatterns=auth
```

### Build Service
```bash
npm run build auth-service
```

## Architecture

### Shared Libraries Used
- `@app/auth` - Authentication guards, strategies, and services
- `@app/database` - Database entities and connection
- `@app/validation` - DTOs and validation rules

### Key Components
- **AuthController** - HTTP endpoints
- **AuthService** - Business logic
- **JwtStrategy** - JWT token validation
- **LocalStrategy** - Username/password validation
- **Guards** - Route protection
- **Decorators** - Metadata and utility decorators

## Error Handling

### Common Error Responses

**409 Conflict - User Exists**
```json
{
  "statusCode": 409,
  "message": "User already exists with this email or phone number"
}
```

**401 Unauthorized - Invalid Credentials**
```json
{
  "statusCode": 401,
  "message": "Invalid credentials"
}
```

**400 Bad Request - Invalid OTP**
```json
{
  "statusCode": 400,
  "message": "Invalid or expired OTP"
}
```

**429 Too Many Requests - Rate Limited**
```json
{
  "statusCode": 429,
  "message": "Too Many Requests"
}
```

## Development

### Adding New Endpoints
1. Add method to `AuthController`
2. Implement business logic in `AuthService`
3. Add appropriate guards and decorators
4. Create tests
5. Update documentation

### Testing Strategy
- Unit tests for controllers and services
- Integration tests for authentication flows
- E2E tests for complete user journeys
- Security tests for vulnerabilities

## Next Steps
- Implement role-based access control
- Add password reset functionality
- Integrate SMS/email providers
- Add OAuth providers (Google, Facebook)
- Implement 2FA support