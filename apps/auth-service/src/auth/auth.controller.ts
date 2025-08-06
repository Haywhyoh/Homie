import { 
  Controller, 
  Post, 
  Body, 
  UseGuards, 
  Request,
  Get,
  HttpStatus,
  HttpCode
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { 
  AuthService, 
  LocalAuthGuard, 
  JwtAuthGuard,
  RolesGuard,
  Public,
  CurrentUser,
  Roles,
  RequirePermissions
} from '@app/auth';
import { 
  RegisterDto, 
  LoginDto, 
  VerifyOtpDto, 
  RefreshTokenDto,
  ResetPasswordDto,
  ConfirmPasswordResetDto
} from '@app/validation';
import { User } from '@app/database';

@ApiTags('Authentication')
@Controller('auth')
@UseGuards(ThrottlerGuard) // Rate limiting
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ 
    status: 201, 
    description: 'User registered successfully. OTP sent for verification.' 
  })
  @ApiResponse({ 
    status: 409, 
    description: 'User already exists with this email or phone number' 
  })
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('verify-otp')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify OTP code' })
  @ApiResponse({ 
    status: 200, 
    description: 'OTP verified successfully' 
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Invalid or expired OTP' 
  })
  async verifyOtp(@Body() verifyOtpDto: VerifyOtpDto) {
    return this.authService.verifyOTP(verifyOtpDto);
  }

  @Post('login')
  @Public()
  @UseGuards(LocalAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login user' })
  @ApiResponse({ 
    status: 200, 
    description: 'User logged in successfully',
    schema: {
      type: 'object',
      properties: {
        accessToken: { type: 'string' },
        refreshToken: { type: 'string' },
        user: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            firstName: { type: 'string' },
            lastName: { type: 'string' },
            email: { type: 'string' },
            phoneNumber: { type: 'string' },
            isVerified: { type: 'boolean' }
          }
        }
      }
    }
  })
  @ApiResponse({ 
    status: 401, 
    description: 'Invalid credentials or account not verified' 
  })
  async login(@Body() loginDto: LoginDto, @Request() req: any) {
    const deviceInfo = {
      deviceId: req.headers['x-device-id'],
      deviceType: req.headers['x-device-type'],
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    };

    return this.authService.login(loginDto, deviceInfo);
  }

  @Post('refresh')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ 
    status: 200, 
    description: 'Tokens refreshed successfully' 
  })
  @ApiResponse({ 
    status: 401, 
    description: 'Invalid refresh token' 
  })
  async refresh(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshTokens(refreshTokenDto.refreshToken);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Logout user' })
  @ApiResponse({ 
    status: 200, 
    description: 'User logged out successfully' 
  })
  async logout(
    @CurrentUser() user: User,
    @Body() body?: { refreshToken?: string }
  ) {
    return this.authService.logout(user.id, body?.refreshToken);
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiResponse({ 
    status: 200, 
    description: 'User profile retrieved successfully' 
  })
  async getProfile(@CurrentUser() user: User) {
    return {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      phoneNumber: user.phoneNumber,
      isVerified: user.isVerified,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  @Get('health')
  @Public()
  @ApiOperation({ summary: 'Health check for auth service' })
  @ApiResponse({ 
    status: 200, 
    description: 'Service is healthy' 
  })
  getHealth() {
    return {
      status: 'healthy',
      service: 'auth-service',
      timestamp: new Date().toISOString(),
    };
  }

  @Post('reset-password')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Initiate password reset' })
  @ApiResponse({ 
    status: 200, 
    description: 'Password reset code sent to email (if email exists)' 
  })
  async initiatePasswordReset(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.initiatePasswordReset(resetPasswordDto);
  }

  @Post('confirm-reset-password')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Confirm password reset with OTP' })
  @ApiResponse({ 
    status: 200, 
    description: 'Password reset successfully' 
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Invalid or expired reset code' 
  })
  async confirmPasswordReset(@Body() confirmResetDto: ConfirmPasswordResetDto) {
    return this.authService.confirmPasswordReset(confirmResetDto);
  }

  @Get('me/roles')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user roles and permissions' })
  @ApiResponse({ 
    status: 200, 
    description: 'User roles and permissions retrieved successfully' 
  })
  async getUserRoles(@CurrentUser() user: User) {
    return {
      roles: user.getRoleNames(),
      permissions: user.getAllPermissions(),
    };
  }

  @Get('admin/test')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin', 'super_admin')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Test admin-only endpoint' })
  @ApiResponse({ 
    status: 200, 
    description: 'Admin access confirmed' 
  })
  @ApiResponse({ 
    status: 403, 
    description: 'Insufficient permissions' 
  })
  async adminTest(@CurrentUser() user: User) {
    return {
      message: 'Admin access granted',
      user: user.email,
      roles: user.getRoleNames(),
    };
  }
}