# HoodMe Backend - Community App for Nigeria

A microservices-based backend for a community app that fosters neighborhood connections, information exchange, and collaboration across Nigeria.

## Architecture Overview

This project follows a microservices architecture with the following services:

- **API Gateway** - Routes requests to appropriate services
- **Auth Service** - Authentication and authorization
- **User Service** - User profile management
- **Social Service** - Social feed and posts
- **Messaging Service** - Real-time messaging
- **Marketplace Service** - Local marketplace and services
- **Events Service** - Community events and calendar
- **Notification Service** - Push notifications and alerts

## Project Structure

```
HoodMe-backend/
├── apps/                    # Microservices
│   ├── api-gateway/         # API Gateway service
│   ├── auth-service/        # Authentication service
│   ├── user-service/        # User management service
│   ├── social-service/      # Social feed service
│   ├── messaging-service/   # Real-time messaging service
│   ├── marketplace-service/ # Marketplace service
│   ├── events-service/      # Events service
│   └── notification-service/# Notification service
├── libs/                    # Shared libraries
│   ├── common/             # Common utilities and decorators
│   ├── database/           # Database entities and migrations
│   ├── auth/               # Authentication guards and strategies
│   └── validation/         # Validation pipes and DTOs
├── docker-compose.yml      # Development infrastructure
└── package.json           # Dependencies and scripts
```

## Quick Start

### Prerequisites

- Node.js 18+
- Docker and Docker Compose
- npm or yarn

### Installation

1. **Clone and setup the project:**
```bash
   cd HoodMe-backend
   npm install
   ```

2. **Setup environment variables:**
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

3. **Start development infrastructure:**
   ```bash
   docker-compose up -d
   ```

4. **Run database migrations:**
   ```bash
   npm run migration:run
   ```

5. **Start all services in development mode:**
```bash
   npm run start:dev
   ```

### Individual Service Commands

Start individual services:

```bash
npm run start:auth        # Auth service (port 3001)
npm run start:user        # User service (port 3002)
npm run start:social      # Social service (port 3003)
npm run start:messaging   # Messaging service (port 3004)
npm run start:marketplace # Marketplace service (port 3005)
npm run start:events      # Events service (port 3006)
npm run start:notification # Notification service (port 3007)
npm run start:gateway     # API Gateway (port 3000)
```

## Development Infrastructure

The project includes Docker Compose configuration for:

- **PostgreSQL** with PostGIS extension (port 5432)
- **Redis** for caching and sessions (port 6379)
- **MinIO** for object storage (port 9000, console: 9001)
- **RabbitMQ** for message queuing (port 5672, management: 15672)

## Available Scripts

- `npm run start:dev` - Start all services in watch mode
- `npm run build` - Build all services
- `npm run test` - Run tests
- `npm run test:cov` - Run tests with coverage
- `npm run lint` - Lint and fix code
- `npm run format` - Format code with Prettier

## API Documentation

Once services are running, Swagger documentation is available at:

- API Gateway: http://localhost:3000/api
- Auth Service: http://localhost:3001/api
- User Service: http://localhost:3002/api
- (and so on for other services)

## Key Features

- ✅ Microservices architecture with NestJS
- ✅ JWT-based authentication with refresh tokens
- ✅ Role-based access control (RBAC)
- ✅ Real-time messaging with WebSocket
- ✅ File upload and media handling
- ✅ Push notifications (FCM)
- ✅ SMS verification for Nigerian phone numbers
- ✅ Geographic location services
- ✅ Content moderation
- ✅ Rate limiting and security middleware

## Technology Stack

- **Framework:** NestJS with TypeScript
- **Database:** PostgreSQL with PostGIS
- **Cache:** Redis
- **Message Queue:** RabbitMQ
- **Object Storage:** MinIO (S3 compatible)
- **Authentication:** JWT with Passport
- **Real-time:** Socket.io
- **Documentation:** Swagger/OpenAPI
- **Testing:** Jest
- **Validation:** class-validator
- **ORM:** TypeORM

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for your changes
4. Ensure all tests pass
5. Submit a pull request

## Environment Variables

Copy `env.example` to `.env` and configure:

- Database connection settings
- JWT secrets
- External service API keys (Twilio, FCM, etc.)
- Storage configuration

## License

This project is licensed under the MIT License.