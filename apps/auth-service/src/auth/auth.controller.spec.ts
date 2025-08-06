import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from '@app/auth';
import { ThrottlerModule } from '@nestjs/throttler';
import { User } from '@app/database';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: jest.Mocked<AuthService>;

  beforeEach(async () => {
    const mockAuthService = {
      register: jest.fn(),
      verifyOTP: jest.fn(),
      login: jest.fn(),
      refreshTokens: jest.fn(),
      logout: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      imports: [
        ThrottlerModule.forRoot([{
          ttl: 60000,
          limit: 10,
        }]),
      ],
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get(AuthService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('register', () => {
    it('should register a new user', async () => {
      const registerDto = {
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        password: 'SecurePass123!',
      };

      const expectedResult = {
        message: 'Registration successful. Please verify your account.',
        userId: 'test-user-id',
      };

      authService.register.mockResolvedValue(expectedResult);

      const result = await controller.register(registerDto);

      expect(authService.register).toHaveBeenCalledWith(registerDto);
      expect(result).toEqual(expectedResult);
    });
  });

  describe('login', () => {
    it('should login a user successfully', async () => {
      const loginDto = {
        login: 'test@example.com',
        password: 'SecurePass123!',
      };

      const mockRequest = {
        headers: {
          'x-device-id': 'device-123',
          'x-device-type': 'mobile',
          'user-agent': 'test-agent',
        },
        ip: '127.0.0.1',
      };

      const expectedResult = {
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        user: {
          id: 'user-id',
          firstName: 'John',
          lastName: 'Doe',
          email: 'test@example.com',
          isVerified: true,
        },
      };

      authService.login.mockResolvedValue(expectedResult);

      const result = await controller.login(loginDto, mockRequest);

      expect(authService.login).toHaveBeenCalledWith(loginDto, {
        deviceId: 'device-123',
        deviceType: 'mobile',
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
      });
      expect(result).toEqual(expectedResult);
    });
  });

  describe('getHealth', () => {
    it('should return health status', () => {
      const result = controller.getHealth();

      expect(result.status).toBe('healthy');
      expect(result.service).toBe('auth-service');
      expect(result.timestamp).toBeDefined();
    });
  });

  describe('getProfile', () => {
    it('should return user profile', async () => {
      const mockUser = {
        id: 'user-id',
        firstName: 'John',
        lastName: 'Doe',
        email: 'test@example.com',
        phoneNumber: '+2348123456789',
        isVerified: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      } as User;

      const result = await controller.getProfile(mockUser);

      expect(result).toEqual({
        id: mockUser.id,
        firstName: mockUser.firstName,
        lastName: mockUser.lastName,
        email: mockUser.email,
        phoneNumber: mockUser.phoneNumber,
        isVerified: mockUser.isVerified,
        createdAt: mockUser.createdAt,
        updatedAt: mockUser.updatedAt,
      });
    });
  });
});