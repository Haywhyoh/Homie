import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';

export class LoginDto {
  @ApiProperty({ 
    example: 'user@example.com',
    description: 'Email address or phone number' 
  })
  @IsString({ message: 'Login must be a string' })
  @IsNotEmpty({ message: 'Login is required' })
  @Transform(({ value }) => value?.toLowerCase().trim())
  login: string;

  @ApiProperty({ 
    example: 'SecurePass123!',
    description: 'User password' 
  })
  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  password: string;
}