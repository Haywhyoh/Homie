import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TransactionalEmailsApi } from '@getbrevo/brevo';
import * as handlebars from 'handlebars';
import * as fs from 'fs';
import * as path from 'path';

export interface EmailOptions {
  to: string | string[];
  subject: string;
  template: string;
  context?: Record<string, any>;
  attachments?: Array<{
    name: string;
    content: string; // base64 encoded
  }>;
}

export interface OtpEmailData {
  firstName: string;
  otpCode: string;
  expiresIn: number; // minutes
  purpose: 'registration' | 'login' | 'password_reset';
}

export interface WelcomeEmailData {
  firstName: string;
  lastName: string;
  email: string;
  neighborhoodName?: string;
}

export interface PasswordResetEmailData {
  firstName: string;
  resetCode: string;
  expiresIn: number; // minutes
}

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private brevoApi: TransactionalEmailsApi;
  private defaultSender: { name: string; email: string };

  constructor(private configService: ConfigService) {
    this.initializeBrevo();
    this.initializeHandlebars();
    this.defaultSender = {
      name: this.configService.get<string>('EMAIL_FROM_NAME', 'HoodMe Community'),
      email: this.configService.get<string>('EMAIL_FROM_ADDRESS', 'ayomide@codemygig.com'),
    };
  }

  private initializeBrevo() {
    const apiKey = this.configService.get<string>('BREVO_API_KEY');
    if (!apiKey) {
      this.logger.warn('BREVO_API_KEY not found. Email service will not function properly.');
      return;
    }

    this.brevoApi = new TransactionalEmailsApi();
    this.brevoApi.setApiKey(0, apiKey); // 0 is the apiKey enum value
    this.logger.log('Brevo email service initialized successfully');
  }

  private initializeHandlebars() {
    // Register Handlebars helpers
    handlebars.registerHelper('eq', function (a, b) {
      return a === b;
    });

    handlebars.registerHelper('ne', function (a, b) {
      return a !== b;
    });

    handlebars.registerHelper('and', function (a, b) {
      return a && b;
    });

    handlebars.registerHelper('or', function (a, b) {
      return a || b;
    });
  }

  async sendEmail(options: EmailOptions): Promise<boolean> {
    try {
      if (!this.brevoApi) {
        throw new Error('Brevo API not initialized');
      }

      const template = await this.loadTemplate(options.template);
      const compiledTemplate = handlebars.compile(template);
      const htmlContent = compiledTemplate(options.context || {});

      const sendSmtpEmail = {
        to: Array.isArray(options.to) 
          ? options.to.map(email => ({ email }))
          : [{ email: options.to }],
        sender: this.defaultSender,
        subject: options.subject,
        htmlContent,
        attachment: options.attachments?.map(att => ({
          name: att.name,
          content: att.content,
        })),
      };

      const result = await this.brevoApi.sendTransacEmail(sendSmtpEmail);
      this.logger.log(`Email sent successfully to ${options.to}. Message ID: ${result.body.messageId}`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to send email to ${options.to}:`, error);
      return false;
    }
  }

  async sendOtpEmail(email: string, data: OtpEmailData): Promise<boolean> {
    const subject = this.getOtpEmailSubject(data.purpose);
    
    return this.sendEmail({
      to: email,
      subject,
      template: 'otp-verification',
      context: {
        ...data,
        brandName: 'HoodMe Community',
        supportEmail: 'support@HoodMecommunity.ng',
        currentYear: new Date().getFullYear(),
      },
    });
  }

  async sendWelcomeEmail(email: string, data: WelcomeEmailData): Promise<boolean> {
    return this.sendEmail({
      to: email,
      subject: 'Welcome to HoodMe Community! 🏠',
      template: 'welcome',
      context: {
        ...data,
        brandName: 'HoodMe Community',
        supportEmail: 'support@HoodMecommunity.ng',
        currentYear: new Date().getFullYear(),
        loginUrl: this.configService.get<string>('FRONTEND_URL', 'https://app.HoodMecommunity.ng') + '/login',
        dashboardUrl: this.configService.get<string>('FRONTEND_URL', 'https://app.HoodMecommunity.ng') + '/dashboard',
      },
    });
  }

  async sendPasswordResetEmail(email: string, data: PasswordResetEmailData): Promise<boolean> {
    return this.sendEmail({
      to: email,
      subject: 'Reset Your HoodMe Community Password 🔐',
      template: 'password-reset',
      context: {
        ...data,
        brandName: 'HoodMe Community',
        supportEmail: 'support@HoodMecommunity.ng',
        currentYear: new Date().getFullYear(),
        resetUrl: this.configService.get<string>('FRONTEND_URL', 'https://app.HoodMecommunity.ng') + '/reset-password',
      },
    });
  }

  async sendNotificationEmail(email: string, subject: string, templateData: Record<string, any>): Promise<boolean> {
    return this.sendEmail({
      to: email,
      subject,
      template: 'notification',
      context: {
        ...templateData,
        brandName: 'HoodMe Community',
        supportEmail: 'support@HoodMecommunity.ng',
        currentYear: new Date().getFullYear(),
      },
    });
  }

  private async loadTemplate(templateName: string): Promise<string> {
    try {
      const templatePath = path.join(__dirname, '..', 'templates', `${templateName}.hbs`);
      return fs.readFileSync(templatePath, 'utf-8');
    } catch (error) {
      this.logger.error(`Failed to load email template: ${templateName}`, error);
      throw new Error(`Email template not found: ${templateName}`);
    }
  }

  private getOtpEmailSubject(purpose: string): string {
    switch (purpose) {
      case 'registration':
        return 'Verify Your HoodMe Community Account 📧';
      case 'login':
        return 'Your HoodMe Community Login Code 🔐';
      case 'password_reset':
        return 'Reset Your HoodMe Community Password 🔒';
      default:
        return 'Your HoodMe Community Verification Code';
    }
  }

  // Test email functionality
  async sendTestEmail(email: string): Promise<boolean> {
    return this.sendEmail({
      to: email,
      subject: 'HoodMe Community - Email Service Test ✅',
      template: 'test',
      context: {
        testTime: new Date().toISOString(),
        brandName: 'HoodMe Community',
        supportEmail: 'support@HoodMecommunity.ng',
        currentYear: new Date().getFullYear(),
      },
    });
  }

  // Bulk email functionality for newsletters, announcements
  async sendBulkEmail(emails: string[], subject: string, templateName: string, context: Record<string, any> = {}): Promise<{ success: number; failed: number }> {
    let success = 0;
    let failed = 0;

    // Process in batches to avoid rate limiting
    const batchSize = 50;
    for (let i = 0; i < emails.length; i += batchSize) {
      const batch = emails.slice(i, i + batchSize);
      
      const promises = batch.map(async (email) => {
        const result = await this.sendEmail({
          to: email,
          subject,
          template: templateName,
          context: {
            ...context,
            brandName: 'HoodMe Community',
            supportEmail: 'support@HoodMecommunity.ng',
            currentYear: new Date().getFullYear(),
          },
        });
        return result ? 'success' : 'failed';
      });

      const results = await Promise.allSettled(promises);
      results.forEach((result) => {
        if (result.status === 'fulfilled' && result.value === 'success') {
          success++;
        } else {
          failed++;
        }
      });

      // Add delay between batches
      if (i + batchSize < emails.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    this.logger.log(`Bulk email completed: ${success} successful, ${failed} failed`);
    return { success, failed };
  }
}