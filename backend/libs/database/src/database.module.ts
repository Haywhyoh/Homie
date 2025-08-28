import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DatabaseService } from './database.service';
import { User, UserSession, OtpVerification, Role, State, LocalGovernmentArea, Neighborhood, Post, PostComment, PostMedia, PostReaction, PostCategory, UserNeighborhood } from './entities';

@Module({
  imports: [
    ConfigModule,
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('DATABASE_HOST', 'localhost'),
        port: configService.get('DATABASE_PORT', 5432),
        username: configService.get('DATABASE_USERNAME', 'HoodMe_user'),
        password: configService.get('DATABASE_PASSWORD', 'HoodMe_password'),
        database: configService.get('DATABASE_NAME', 'HoodMe_dev'),
        entities: [User, UserSession, OtpVerification, Role, State, LocalGovernmentArea, Neighborhood, Post, PostComment, PostMedia, PostReaction, PostCategory, UserNeighborhood],
        migrations: ['libs/database/src/migrations/*{.ts,.js}'],
        synchronize: configService.get('NODE_ENV') === 'development',
        logging: configService.get('NODE_ENV') === 'development',
        ssl: configService.get('NODE_ENV') === 'production' ? {
          rejectUnauthorized: false
        } : false,
      }),
      inject: [ConfigService],
    }),
    TypeOrmModule.forFeature([User, UserSession, OtpVerification, Role, State, LocalGovernmentArea, Neighborhood, Post, PostComment, PostMedia, PostReaction, PostCategory, UserNeighborhood]),
  ],
  providers: [DatabaseService],
  exports: [DatabaseService, TypeOrmModule],
})
export class DatabaseModule {}
