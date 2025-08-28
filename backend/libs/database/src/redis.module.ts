import { Module, Global } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { redisStore } from 'cache-manager-ioredis-yet';

@Global()
@Module({
  imports: [
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => {
        const redisConfig = {
          store: redisStore,
          host: configService.get('REDIS_HOST', 'localhost'),
          port: configService.get('REDIS_PORT', 6379),
          password: configService.get('REDIS_PASSWORD', ''),
          db: configService.get('REDIS_DB', 0),
          retryDelayOnFailover: 100,
          maxRetriesPerRequest: 3,
          lazyConnect: true,
          // Connection pool settings
          family: 4, // 4 (IPv4) or 6 (IPv6)
          keepAlive: true,
          connectTimeout: 10000, // 10 seconds
          commandTimeout: 5000, // 5 seconds
          // Key prefix for this application
          keyPrefix: 'HoodMe:',
          // Default TTL in seconds (1 hour)
          ttl: 3600,
        };

        return redisConfig;
      },
      inject: [ConfigService],
      isGlobal: true,
    }),
  ],
  exports: [CacheModule],
})
export class RedisModule {}