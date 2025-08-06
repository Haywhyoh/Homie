import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule as SharedAuthModule } from '@app/auth';
import { DatabaseModule, User, UserSession, OtpVerification, Role } from '@app/database';
import { AuthController } from './auth.controller';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env'],
    }),
    ThrottlerModule.forRoot([{
      ttl: 60000, // 1 minute
      limit: 10, // 10 requests per minute
    }]),
    DatabaseModule,
    TypeOrmModule.forFeature([User, UserSession, OtpVerification, Role]),
    SharedAuthModule,
  ],
  controllers: [AuthController],
})
export class AuthServiceModule {}