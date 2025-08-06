import { IsString, IsNotEmpty, IsIn, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyOtpDto {
  @ApiProperty({ 
    example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    description: 'User ID' 
  })
  @IsString({ message: 'User ID must be a string' })
  @IsNotEmpty({ message: 'User ID is required' })
  userId: string;

  @ApiProperty({ 
    example: '123456',
    description: '6-digit OTP code' 
  })
  @IsString({ message: 'OTP code must be a string' })
  @Length(6, 6, { message: 'OTP code must be exactly 6 digits' })
  otpCode: string;

  @ApiProperty({ 
    example: 'registration',
    description: 'Purpose of OTP verification',
    enum: ['registration', 'login', 'password_reset']
  })
  @IsString({ message: 'Purpose must be a string' })
  @IsIn(['registration', 'login', 'password_reset'], { 
    message: 'Purpose must be one of: registration, login, password_reset' 
  })
  purpose: 'registration' | 'login' | 'password_reset';
}