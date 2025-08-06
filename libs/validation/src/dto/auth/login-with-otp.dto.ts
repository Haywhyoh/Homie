import { IsEmail, IsString, IsNotEmpty, IsOptional, MinLength, IsIn } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';

export class InitiateOtpLoginDto {
  @ApiProperty({ 
    example: 'user@example.com',
    description: 'Email address for OTP login' 
  })
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string;
}

export class VerifyOtpLoginDto {
  @ApiProperty({ 
    example: 'user@example.com',
    description: 'Email address used for OTP login' 
  })
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string;

  @ApiProperty({ 
    example: '123456',
    description: '6-digit OTP code sent to email' 
  })
  @IsString({ message: 'OTP code must be a string' })
  @IsNotEmpty({ message: 'OTP code is required' })
  @MinLength(6, { message: 'OTP code must be 6 digits' })
  otpCode: string;

  @ApiProperty({ 
    example: 'mobile',
    description: 'Device type for session tracking',
    required: false,
    enum: ['web', 'mobile', 'tablet']
  })
  @IsOptional()
  @IsString()
  @IsIn(['web', 'mobile', 'tablet'], { message: 'Device type must be web, mobile, or tablet' })
  deviceType?: string;

  @ApiProperty({ 
    example: 'iPhone 13 Pro',
    description: 'Device information for session tracking',
    required: false
  })
  @IsOptional()
  @IsString()
  deviceInfo?: string;
}