import { Test, TestingModule } from '@nestjs/testing';
import { AuthServiceService } from './auth-service.service';

describe('AuthServiceService', () => {
  let service: AuthServiceService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AuthServiceService],
    }).compile();

    service = module.get<AuthServiceService>(AuthServiceService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should return hello message', () => {
    expect(service.getHello()).toBe('Hello from Auth Service!');
  });

  it('should return health status', () => {
    const health = service.getHealth();
    expect(health.status).toBe('healthy');
    expect(health.service).toBe('auth-service');
    expect(health.timestamp).toBeDefined();
    expect(typeof health.timestamp).toBe('string');
  });
});