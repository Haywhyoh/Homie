# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**HoodMe** is a comprehensive community application for Nigeria - described as "NextDoor for Nigeria". It consists of two main components:

1. **Mobile App** (`HoodMe_Mobile/`) - React Native with Expo for iOS, Android, and Web
2. **Backend** (`backend/`) - NestJS microservices architecture with PostgreSQL

The application facilitates neighborhood connections, local commerce, community events, and safety features specifically designed for Nigerian communities.

## Repository Structure

```
HoodMe/
├── HoodMe_Mobile/          # React Native mobile application
│   ├── src/                # Mobile app source code
│   ├── assets/             # Images, icons, and media assets
│   └── package.json        # Mobile dependencies and scripts
└── backend/                # NestJS microservices backend
    ├── apps/               # Microservice applications
    ├── libs/               # Shared libraries
    ├── docker-compose.yml  # Development infrastructure
    └── package.json        # Backend dependencies and scripts
```

## Development Commands

### Mobile App (HoodMe_Mobile/)
Navigate to `HoodMe_Mobile/` directory first:

- `npm start` - Start Expo development server
- `npm run ios` - Run on iOS simulator  
- `npm run android` - Run on Android emulator
- `npm run web` - Run on web browser
- No test commands configured yet
- ESLint and Prettier available for code formatting

### Backend (backend/)
Navigate to `backend/` directory first:

**Development:**
- `npm run start:dev` - Start all services in watch mode
- `npm run start:auth` - Start only auth service in watch mode
- `npm run start:user` - Start only user service in watch mode
- `npm run start:social` - Start only social service in watch mode
- `npm run start:messaging` - Start only messaging service in watch mode
- `npm run start:marketplace` - Start only marketplace service in watch mode
- `npm run start:events` - Start only events service in watch mode
- `npm run start:notification` - Start only notification service in watch mode
- `npm run start:gateway` - Start only API gateway in watch mode

**Build & Production:**
- `npm run build` - Build all services
- `npm run start:prod` - Start in production mode

**Code Quality:**
- `npm run lint` - Lint and fix TypeScript code
- `npm run format` - Format code with Prettier

**Testing:**
- `npm run test` - Run unit tests with Jest
- `npm run test:watch` - Run tests in watch mode
- `npm run test:cov` - Run tests with coverage report
- `npm run test:e2e` - Run end-to-end tests
- `npm run test:debug` - Run tests in debug mode

**Database Management:**
- `npm run migration:generate` - Generate new migration based on entity changes
- `npm run migration:create` - Create empty migration file
- `npm run migration:run` - Run pending migrations
- `npm run migration:revert` - Revert last migration
- `npm run schema:sync` - Sync database schema (development only)
- `npm run db:seed` - Seed database with initial data

**Infrastructure:**
- `docker-compose up -d` - Start development infrastructure (PostgreSQL, Redis, MinIO, RabbitMQ)
- `docker-compose down` - Stop infrastructure

## Architecture Overview

### Mobile App Architecture

**Technology Stack:**
- React Native with Expo (~53.0.20)
- TypeScript
- React Navigation v7
- React Native Paper + React Native Elements for UI
- AsyncStorage + SecureStore for local storage
- Expo Location + React Native Maps for location services

**Authentication Flow:**
- New Users: Welcome → Phone Verification → OTP → Location Setup → Main App
- Existing Users: Welcome → Login → Main App
- Legacy Flow: Onboarding → Location Selection → Invitation Code → Main App

**Navigation Structure:**
- Authentication Stack (onboarding/login screens)
- Main Tab Navigator (Home, Feed, Events, Marketplace, Profile)
- Nigerian cultural context: "Estate" and "Compound" terminology

**Design System:**
- Primary Color: `#00A651` (HoodMe Green)
- 8px grid spacing system
- Comprehensive color palette in `src/constants/index.ts`
- Nigerian-specific UI patterns and cultural references

### Backend Architecture

**Microservices (NestJS):**
- **API Gateway** (port 3000) - Request routing and aggregation
- **Auth Service** (port 3001) - JWT authentication, OTP verification
- **User Service** (port 3002) - User profiles and management
- **Social Service** (port 3003) - Community feed and posts
- **Messaging Service** (port 3004) - Real-time messaging
- **Marketplace Service** (port 3005) - Local commerce
- **Events Service** (port 3006) - Community events
- **Notification Service** (port 3007) - Push notifications

**Shared Libraries:**
- `@app/auth` - Authentication guards, strategies, decorators
- `@app/common` - Common utilities and base classes
- `@app/database` - TypeORM entities, migrations, database config
- `@app/validation` - DTOs and validation pipes
- `@app/email` - Email service with Brevo integration

**Technology Stack:**
- NestJS with TypeScript
- PostgreSQL with PostGIS extension
- Redis for caching and sessions
- RabbitMQ for message queuing
- MinIO for S3-compatible object storage
- TypeORM for database operations
- JWT with Passport for authentication
- Swagger/OpenAPI for documentation
- Jest for testing

### Database Infrastructure

**Development Services (Docker Compose):**
- PostgreSQL with PostGIS (port 5432)
- Redis (port 6379) 
- MinIO object storage (port 9000, console 9001)
- RabbitMQ (port 5672, management 15672)

## Key Technical Patterns

### Authentication & Security
- JWT tokens with refresh token rotation
- Role-based access control (RBAC) 
- Nigerian phone number verification with carrier detection
- OTP verification via Brevo email service
- Guards and decorators for route protection

### Database Design
- Geographic data support with PostGIS
- Multi-tenant architecture for neighborhoods/estates
- User verification and trust system
- Content moderation and safety features

### API Design
- RESTful APIs with Swagger documentation
- Consistent DTOs with validation
- Error handling and response formatting
- Rate limiting and security middleware

## Development Guidelines

### Mobile App Development
- Follow design system in `src/constants/index.ts` and `ux.md`
- Use Nigerian cultural context (estate/compound terminology)
- Implement progressive trust building in UX
- Support multiple languages (English, Hausa, Yoruba, Igbo)
- Test on both iOS and Android platforms

### Backend Development
- Follow NestJS best practices and patterns
- Use shared libraries for common functionality
- Write unit tests for all services
- Document APIs with Swagger annotations
- Implement proper error handling and logging
- Use TypeORM migrations for database changes

### Code Quality
- TypeScript strict mode enabled
- ESLint and Prettier for consistent formatting  
- Comprehensive test coverage required
- Security-first approach for all features
- Performance optimization for Nigerian connectivity

## Environment Setup

### Mobile App Environment Variables
Create `.env` in `HoodMe_Mobile/`:
```
EXPO_PUBLIC_API_URL=http://localhost:3000
EXPO_PUBLIC_GOOGLE_MAPS_API_KEY=your_google_maps_api_key
EXPO_PUBLIC_SMS_SERVICE_API_KEY=your_sms_service_api_key
```

### Backend Environment Variables
Copy `backend/env.example` to `backend/.env` and configure:
- Database connection settings
- JWT secrets (separate for access and refresh tokens)
- Brevo email service API keys
- External service configurations (Twilio, FCM, etc.)

## Testing Strategy

### Mobile App Testing
- Unit tests for utility functions (not yet implemented)
- Integration tests for API calls
- E2E tests for critical user flows
- Manual testing on various devices and screen sizes

### Backend Testing
- Unit tests with Jest for all services
- Integration tests for API endpoints
- E2E tests with test database
- Automated testing in CI/CD pipeline
- Coverage reports with Codecov integration

## Development Workflow

### Getting Started
1. Clone repository and navigate to appropriate directory
2. Install dependencies with `npm install`
3. Set up environment variables
4. For backend: Start Docker infrastructure with `docker-compose up -d`
5. For backend: Run database migrations with `npm run migration:run`
6. Start development server with appropriate command

### CI/CD Pipeline
- GitHub Actions workflow for automated testing
- Tests run on Node.js 18.x and 20.x
- PostgreSQL and Redis services in CI environment
- Docker image builds for all microservices
- Code coverage reporting with Codecov

### Code Review Guidelines
- Follow existing code patterns and conventions
- Ensure comprehensive test coverage
- Update documentation for new features
- Security review for authentication/authorization changes
- Performance testing for critical paths

## Nigerian Context Considerations

### Cultural Adaptation
- Use "Estate" and "Compound" instead of "Neighborhood"
- Support Nigerian phone number formats (+234)
- Include major Nigerian cities and states
- Consider local business hours and cultural practices
- Support multiple Nigerian languages where applicable

### Technical Considerations
- Optimize for varying connectivity conditions
- Consider data usage limitations
- Support offline functionality where possible
- Integrate with Nigerian payment systems
- Comply with Nigerian data protection regulations

## Troubleshooting Common Issues

### Mobile App Issues
- Vector icons package needs migration to new model
- Some dependencies show deprecation warnings
- ESLint version needs updating
- Ensure proper platform-specific configuration

### Backend Issues
- Database connection issues: Check Docker services are running
- Migration failures: Ensure database is accessible and schema is valid
- Service communication: Verify all required services are running on correct ports
- Authentication issues: Check JWT secrets and token expiration settings