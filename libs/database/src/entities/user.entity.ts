import { 
  Entity, 
  PrimaryGeneratedColumn, 
  Column, 
  CreateDateColumn, 
  UpdateDateColumn,
  OneToMany,
  Index
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { Exclude } from 'class-transformer';
import { UserNeighborhood } from './user-neighborhood.entity';
import { Post } from './post.entity';
import { UserSession } from './user-session.entity';
import { OtpVerification } from './otp-verification.entity';

@Entity('users')
@Index(['phoneNumber'], { unique: true })
@Index(['email'], { unique: true })
export class User {
  @ApiProperty({ description: 'Unique identifier for the user' })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ description: 'User phone number (Nigerian format)', example: '+2348123456789' })
  @Column({ name: 'phone_number', unique: true, nullable: true })
  phoneNumber?: string;

  @ApiProperty({ description: 'User email address', example: 'user@example.com' })
  @Column({ unique: true })
  email: string;

  @Exclude()
  @Column({ name: 'password_hash' })
  passwordHash: string;

  @ApiProperty({ description: 'User first name', example: 'John' })
  @Column({ name: 'first_name' })
  firstName: string;

  @ApiProperty({ description: 'User last name', example: 'Doe' })
  @Column({ name: 'last_name' })
  lastName: string;

  @ApiProperty({ description: 'Profile picture URL', required: false })
  @Column({ name: 'profile_picture_url', nullable: true })
  profilePictureUrl?: string;

  @ApiProperty({ description: 'Date of birth', required: false })
  @Column({ name: 'date_of_birth', type: 'date', nullable: true })
  dateOfBirth?: Date;

  @ApiProperty({ description: 'User gender', enum: ['male', 'female', 'other'], required: false })
  @Column({ length: 10, nullable: true })
  gender?: string;

  @ApiProperty({ description: 'Whether user account is verified' })
  @Column({ name: 'is_verified', default: false })
  isVerified: boolean;

  @ApiProperty({ description: 'Whether user account is active' })
  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @ApiProperty({ description: 'Preferred language', example: 'en' })
  @Column({ name: 'preferred_language', length: 10, default: 'en' })
  preferredLanguage: string;

  @ApiProperty({ description: 'Last login timestamp', required: false })
  @Column({ name: 'last_login_at', type: 'timestamp', nullable: true })
  lastLoginAt?: Date;

  @ApiProperty({ description: 'Account creation timestamp' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @ApiProperty({ description: 'Last update timestamp' })
  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  // Relations
  @OneToMany(() => UserNeighborhood, userNeighborhood => userNeighborhood.user)
  userNeighborhoods: UserNeighborhood[];

  @OneToMany(() => Post, post => post.user)
  posts: Post[];

  @OneToMany(() => UserSession, session => session.user)
  sessions: UserSession[];

  @OneToMany(() => OtpVerification, otp => otp.user)
  otpVerifications: OtpVerification[];

  // Virtual properties
  @ApiProperty({ description: 'Full name of the user' })
  get fullName(): string {
    return `${this.firstName} ${this.lastName}`;
  }

  // Helper methods
  toJSON() {
    const { passwordHash, ...result } = this;
    return result;
  }
}