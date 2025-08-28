import { IsEmail, IsPhoneNumber, IsString, MinLength, Matches, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';

export class RegisterDto {
  @ApiProperty({ 
    example: 'user@example.com',
    description: 'User email address' 
  })
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string;

  @ApiProperty({ 
    example: '+2348123456789',
    description: 'Nigerian phone number',
    required: false 
  })
  @IsOptional()
  @IsPhoneNumber('NG', { message: 'Please provide a valid Nigerian phone number' })
  phoneNumber?: string;

  @ApiProperty({ 
    example: 'John',
    description: 'User first name' 
  })
  @IsString({ message: 'First name must be a string' })
  @MinLength(2, { message: 'First name must be at least 2 characters long' })
  @Transform(({ value }) => value?.trim())
  firstName: string;

  @ApiProperty({ 
    example: 'Doe',
    description: 'User last name' 
  })
  @IsString({ message: 'Last name must be a string' })
  @MinLength(2, { message: 'Last name must be at least 2 characters long' })
  @Transform(({ value }) => value?.trim())
  lastName: string;

  @ApiProperty({ 
    example: 'SecurePass123!',
    description: 'User password (min 8 chars, must include uppercase, lowercase, number, and special character)' 
  })
  @IsString({ message: 'Password must be a string' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
    { message: 'Password must contain uppercase letter, lowercase letter, number and special character' }
  )
  password: string;
}