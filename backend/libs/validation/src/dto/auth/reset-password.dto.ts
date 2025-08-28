import { IsEmail, IsString, IsNotEmpty, MinLength, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';

export class ResetPasswordDto {
  @ApiProperty({ 
    example: 'user@example.com',
    description: 'Email address for password reset' 
  })
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string;
}

export class ConfirmPasswordResetDto {
  @ApiProperty({ 
    example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    description: 'User ID from password reset initiation' 
  })
  @IsString({ message: 'User ID must be a string' })
  @IsNotEmpty({ message: 'User ID is required' })
  userId: string;

  @ApiProperty({ 
    example: '123456',
    description: '6-digit OTP code sent to email' 
  })
  @IsString({ message: 'OTP code must be a string' })
  @IsNotEmpty({ message: 'OTP code is required' })
  otpCode: string;

  @ApiProperty({ 
    example: 'NewSecurePass123!',
    description: 'New password (min 8 chars, must include uppercase, lowercase, number, and special character)' 
  })
  @IsString({ message: 'Password must be a string' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
    { message: 'Password must contain uppercase letter, lowercase letter, number and special character' }
  )
  newPassword: string;
}