import { Module } from '@nestjs/common';
import { AuthServiceController } from './auth-service.controller';
import { AuthServiceService } from './auth-service.service';
import { DatabaseModule, RedisModule } from '@app/database';
import { EmailModule } from '@app/email';
import { AuthServiceModule as AuthModule } from './auth/auth.module';

@Module({
  imports: [
    DatabaseModule, 
    RedisModule,
    EmailModule,
    AuthModule,
  ],
  controllers: [AuthServiceController],
  providers: [AuthServiceService],
})
export class AuthServiceModule {}
