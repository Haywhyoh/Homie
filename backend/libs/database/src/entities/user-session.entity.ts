import { 
  Entity, 
  PrimaryGeneratedColumn, 
  Column, 
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { Exclude } from 'class-transformer';
import { User } from './user.entity';

@Entity('user_sessions')
@Index(['userId'])
@Index(['deviceId'])
export class UserSession {
  @ApiProperty({ description: 'Unique identifier for the session' })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ description: 'User ID this session belongs to' })
  @Column({ name: 'user_id' })
  userId: string;

  @ApiProperty({ description: 'Device identifier' })
  @Column({ name: 'device_id', nullable: true })
  deviceId?: string;

  @ApiProperty({ description: 'Device type', example: 'mobile' })
  @Column({ name: 'device_type', length: 50, nullable: true })
  deviceType?: string;

  @Exclude()
  @Column({ name: 'refresh_token_hash', nullable: true })
  refreshTokenHash?: string;

  @ApiProperty({ description: 'IP address of the session' })
  @Column({ name: 'ip_address', type: 'inet', nullable: true })
  ipAddress?: string;

  @ApiProperty({ description: 'User agent string' })
  @Column({ name: 'user_agent', type: 'text', nullable: true })
  userAgent?: string;

  @ApiProperty({ description: 'Whether session is active' })
  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @ApiProperty({ description: 'Session expiration time' })
  @Column({ name: 'expires_at', type: 'timestamp' })
  expiresAt: Date;

  @ApiProperty({ description: 'Session creation timestamp' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  // Relations
  @ManyToOne(() => User, user => user.sessions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  // Helper methods
  isExpired(): boolean {
    return new Date() > this.expiresAt;
  }

  isValidSession(): boolean {
    return this.isActive && !this.isExpired();
  }
}