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
import { EmailService, OtpEmailData, WelcomeEmailData, PasswordResetEmailData } from '@app/email';

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

export interface InitiateOtpLoginDto {
  email: string;
}

export interface VerifyOtpLoginDto {
  email: string;
  otpCode: string;
  deviceType?: string;
  deviceInfo?: string;
}

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    private emailService: EmailService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(UserSession)
    private sessionRepository: Repository<UserSession>,
    @InjectRepository(OtpVerification)
    private otpRepository: Repository<OtpVerification>,
  ) {}

  private generateOTP(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

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
      // Generate and send OTP for email verification
      const otpCode = this.generateOTP();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      // Store OTP
      await this.otpRepository.save({
        userId: user.id,
        otpCode,
        purpose: 'registration',
        expiresAt,
        isUsed: false,
      });

      // Send OTP email
      const emailData: OtpEmailData = {
        firstName: user.firstName,
        otpCode,
        expiresIn: 10,
        purpose: 'registration',
      };

      await this.emailService.sendOtpEmail(user.email, emailData);
    }

    // Send welcome email (async, don't wait)
    const welcomeEmailData: WelcomeEmailData = {
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
    };
    this.emailService.sendWelcomeEmail(user.email, welcomeEmailData).catch(error => {
      console.error('Failed to send welcome email:', error);
    });

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
    const otpCode = this.generateOTP();
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

    // Generate and send OTP for password reset
    const otpCode = this.generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Store OTP
    await this.otpRepository.save({
      userId: user.id,
      otpCode,
      purpose: 'password_reset',
      expiresAt,
      isUsed: false,
    });

    // Send password reset email
    const emailData: PasswordResetEmailData = {
      firstName: user.firstName,
      resetCode: otpCode,
      expiresIn: 10,
    };

    await this.emailService.sendPasswordResetEmail(user.email, emailData);

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

  async initiateOtpLogin(initiateOtpDto: InitiateOtpLoginDto): Promise<{ message: string; userId?: string }> {
    const user = await this.userRepository.findOne({
      where: { email: initiateOtpDto.email },
    });

    if (!user) {
      // Don't reveal if email exists for security
      return { message: 'If the email exists, a login code has been sent.' };
    }

    if (!user.isActive) {
      throw new BadRequestException('Account is deactivated');
    }

    if (!user.isVerified) {
      throw new BadRequestException('Please verify your account first');
    }

    // Generate and send OTP for login
    const otpCode = this.generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Store OTP
    await this.otpRepository.save({
      userId: user.id,
      otpCode,
      purpose: 'login',
      expiresAt,
      isUsed: false,
    });

    // Send OTP email
    const emailData: OtpEmailData = {
      firstName: user.firstName,
      otpCode,
      expiresIn: 10,
      purpose: 'login',
    };

    await this.emailService.sendOtpEmail(user.email, emailData);

    return { 
      message: 'If the email exists, a login code has been sent.',
      userId: user.id // Only for development/testing
    };
  }

  async verifyOtpLogin(verifyOtpDto: VerifyOtpLoginDto): Promise<AuthResponse> {
    const user = await this.userRepository.findOne({
      where: { email: verifyOtpDto.email },
      relations: ['roles'],
    });

    if (!user) {
      throw new UnauthorizedException('Invalid email or OTP');
    }

    if (!user.isActive) {
      throw new BadRequestException('Account is deactivated');
    }

    if (!user.isVerified) {
      throw new BadRequestException('Please verify your account first');
    }

    // Verify OTP
    const otpVerification = await this.verifyOTP({
      userId: user.id,
      otpCode: verifyOtpDto.otpCode,
      purpose: 'login',
    });

    if (!otpVerification.verified) {
      throw new UnauthorizedException('Invalid or expired login code');
    }

    // Generate tokens
    const tokens = await this.generateTokens(user);

    // Store session
    const deviceInfo = {
      type: verifyOtpDto.deviceType || 'web',
      info: verifyOtpDto.deviceInfo || 'Unknown Device',
      loginMethod: 'otp_email',
    };

    await this.storeSession(user.id, tokens.refreshToken, deviceInfo);

    return tokens;
  }

  async testEmailService(email: string): Promise<{ message: string; success: boolean }> {
    try {
      const success = await this.emailService.sendTestEmail(email);
      return {
        message: success ? 'Test email sent successfully' : 'Failed to send test email',
        success,
      };
    } catch (error) {
      return {
        message: `Email service error: ${error.message}`,
        success: false,
      };
    }
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