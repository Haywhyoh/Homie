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
import { User } from './user.entity';

@Entity('otp_verifications')
@Index(['userId'])
@Index(['contactValue'])
export class OtpVerification {
  @ApiProperty({ description: 'Unique identifier for the OTP verification' })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ description: 'User ID this OTP belongs to' })
  @Column({ name: 'user_id' })
  userId: string;

  @ApiProperty({ description: 'Contact method used', enum: ['phone', 'email'] })
  @Column({ name: 'contact_method', length: 50 })
  contactMethod: string;

  @ApiProperty({ description: 'The actual contact value (phone/email)' })
  @Column({ name: 'contact_value' })
  contactValue: string;

  @Column({ name: 'otp_code', length: 6 })
  otpCode: string;

  @ApiProperty({ description: 'Purpose of OTP', enum: ['registration', 'login', 'password_reset'] })
  @Column({ length: 50 })
  purpose: string;

  @ApiProperty({ description: 'OTP expiration time' })
  @Column({ name: 'expires_at', type: 'timestamp' })
  expiresAt: Date;

  @ApiProperty({ description: 'Whether OTP has been used' })
  @Column({ name: 'is_used', default: false })
  isUsed: boolean;

  @ApiProperty({ description: 'OTP creation timestamp' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  // Relations
  @ManyToOne(() => User, user => user.otpVerifications, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  // Helper methods
  isExpired(): boolean {
    return new Date() > this.expiresAt;
  }

  isValid(): boolean {
    return !this.isUsed && !this.isExpired();
  }
}