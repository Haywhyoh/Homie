import { 
  Injectable, 
  UnauthorizedException, 
  ConflictException,
  BadRequestException 
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User, UserSession, OtpVerification } from '@app/database';
import { JwtPayload } from './strategies/jwt.strategy';

export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    firstName: string;
    lastName: string;
    email: string;
    phoneNumber?: string;
    isVerified: boolean;
  };
}

export interface RegisterDto {
  email: string;
  phoneNumber?: string;
  firstName: string;
  lastName: string;
  password: string;
}

export interface LoginDto {
  login: string; // email or phone
  password: string;
}

export interface VerifyOtpDto {
  userId: string;
  otpCode: string;
  purpose: 'registration' | 'login' | 'password_reset';
}

export interface ResetPasswordDto {
  email: string;
}

export interface ConfirmPasswordResetDto {
  userId: string;
  otpCode: string;
  newPassword: string;
}

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(UserSession)
    private sessionRepository: Repository<UserSession>,
    @InjectRepository(OtpVerification)
    private otpRepository: Repository<OtpVerification>,
  ) {}

  async register(registerDto: RegisterDto): Promise<{ message: string; userId: string }> {
    // Check if user exists
    const existingUser = await this.userRepository.findOne({
      where: [
        { email: registerDto.email },
        ...(registerDto.phoneNumber ? [{ phoneNumber: registerDto.phoneNumber }] : []),
      ],
    });

    if (existingUser) {
      throw new ConflictException('User already exists with this email or phone number');
    }

    // Hash password
    const saltRounds = this.configService.get<number>('BCRYPT_SALT_ROUNDS', 12);
    const passwordHash = await bcrypt.hash(registerDto.password, saltRounds);

    // Create user
    const user = await this.userRepository.save({
      ...registerDto,
      passwordHash,
      isVerified: false,
      isActive: true,
    });

    // Send OTP for verification
    if (registerDto.phoneNumber) {
      await this.sendOTP(user.id, registerDto.phoneNumber, 'phone', 'registration');
    } else {
      await this.sendOTP(user.id, registerDto.email, 'email', 'registration');
    }

    return {
      message: 'Registration successful. Please verify your account.',
      userId: user.id,
    };
  }

  async validateUser(login: string, password: string): Promise<User | null> {
    const user = await this.userRepository.findOne({
      where: [
        { email: login },
        { phoneNumber: login },
      ],
    });

    if (!user || !user.isActive) {
      return null;
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return null;
    }

    return user;
  }

  async login(loginDto: LoginDto, deviceInfo?: any): Promise<AuthResponse> {
    const user = await this.validateUser(loginDto.login, loginDto.password);
    
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isVerified) {
      throw new UnauthorizedException('Please verify your account first');
    }

    // Update last login
    await this.userRepository.update(user.id, { lastLoginAt: new Date() });

    return this.generateTokens(user, deviceInfo);
  }

  async generateTokens(user: User, deviceInfo?: any): Promise<AuthResponse> {
    const payload: Omit<JwtPayload, 'type'> = {
      sub: user.id,
      email: user.email,
      phoneNumber: user.phoneNumber,
      roles: [], // TODO: Implement roles
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        { ...payload, type: 'access' },
        { 
          expiresIn: this.configService.get<string>('JWT_EXPIRES_IN', '15m'),
          secret: this.configService.get<string>('JWT_SECRET'),
        },
      ),
      this.jwtService.signAsync(
        { ...payload, type: 'refresh' },
        { 
          expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRES_IN', '30d'),
          secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        },
      ),
    ]);

    // Store refresh token session
    await this.storeSession(user.id, refreshToken, deviceInfo);

    return {
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        phoneNumber: user.phoneNumber,
        isVerified: user.isVerified,
      },
    };
  }

  async refreshTokens(refreshToken: string): Promise<AuthResponse> {
    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });

      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Invalid token type');
      }

      // Check if session exists and is valid
      const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
      const session = await this.sessionRepository.findOne({
        where: { 
          userId: payload.sub,
          isActive: true,
        },
        relations: ['user'],
      });

      if (!session || !session.isValidSession()) {
        throw new UnauthorizedException('Invalid session');
      }

      // Generate new tokens
      return this.generateTokens(session.user);
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async sendOTP(
    userId: string, 
    contactValue: string, 
    contactMethod: 'phone' | 'email', 
    purpose: 'registration' | 'login' | 'password_reset'
  ): Promise<void> {
    // Invalidate existing OTPs
    await this.otpRepository.update(
      { userId, purpose, isUsed: false },
      { isUsed: true }
    );

    // Generate 6-digit OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await this.otpRepository.save({
      userId,
      contactMethod,
      contactValue,
      otpCode,
      purpose,
      expiresAt,
      isUsed: false,
    });

    // TODO: Implement actual SMS/Email sending
    console.log(`OTP for ${contactValue}: ${otpCode}`);
  }

  async verifyOTP(verifyOtpDto: VerifyOtpDto): Promise<{ message: string; verified: boolean }> {
    const otp = await this.otpRepository.findOne({
      where: {
        userId: verifyOtpDto.userId,
        otpCode: verifyOtpDto.otpCode,
        purpose: verifyOtpDto.purpose,
        isUsed: false,
      },
    });

    if (!otp || !otp.isValid()) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    // Mark OTP as used
    await this.otpRepository.update(otp.id, { isUsed: true });

    // If registration OTP, verify the user
    if (verifyOtpDto.purpose === 'registration') {
      await this.userRepository.update(verifyOtpDto.userId, { isVerified: true });
    }

    return {
      message: 'OTP verified successfully',
      verified: true,
    };
  }

  async logout(userId: string, refreshToken?: string): Promise<{ message: string }> {
    if (refreshToken) {
      // Invalidate specific session
      await this.sessionRepository.update(
        { userId, refreshTokenHash: await bcrypt.hash(refreshToken, 10) },
        { isActive: false }
      );
    } else {
      // Invalidate all sessions for user
      await this.sessionRepository.update(
        { userId, isActive: true },
        { isActive: false }
      );
    }

    return { message: 'Logged out successfully' };
  }

  async initiatePasswordReset(resetPasswordDto: ResetPasswordDto): Promise<{ message: string; userId?: string }> {
    const user = await this.userRepository.findOne({
      where: { email: resetPasswordDto.email },
    });

    if (!user) {
      // Don't reveal if email exists for security
      return { message: 'If the email exists, a password reset code has been sent.' };
    }

    if (!user.isActive) {
      throw new BadRequestException('Account is deactivated');
    }

    // Send OTP for password reset
    await this.sendOTP(user.id, user.email, 'email', 'password_reset');

    return { 
      message: 'If the email exists, a password reset code has been sent.',
      userId: user.id // Only for development/testing
    };
  }

  async confirmPasswordReset(confirmResetDto: ConfirmPasswordResetDto): Promise<{ message: string }> {
    // Verify OTP first
    const otpVerification = await this.verifyOTP({
      userId: confirmResetDto.userId,
      otpCode: confirmResetDto.otpCode,
      purpose: 'password_reset',
    });

    if (!otpVerification.verified) {
      throw new BadRequestException('Invalid or expired reset code');
    }

    // Hash new password
    const saltRounds = this.configService.get<number>('BCRYPT_SALT_ROUNDS', 12);
    const passwordHash = await bcrypt.hash(confirmResetDto.newPassword, saltRounds);

    // Update user password
    await this.userRepository.update(confirmResetDto.userId, { passwordHash });

    // Invalidate all existing sessions for security
    await this.sessionRepository.update(
      { userId: confirmResetDto.userId, isActive: true },
      { isActive: false }
    );

    return { message: 'Password has been reset successfully. Please log in with your new password.' };
  }

  private async storeSession(userId: string, refreshToken: string, deviceInfo?: any): Promise<void> {
    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    await this.sessionRepository.save({
      userId,
      deviceId: deviceInfo?.deviceId,
      deviceType: deviceInfo?.deviceType,
      refreshTokenHash,
      ipAddress: deviceInfo?.ipAddress,
      userAgent: deviceInfo?.userAgent,
      isActive: true,
      expiresAt,
    });
  }
}