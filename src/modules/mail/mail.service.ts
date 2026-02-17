import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { I18nService } from 'nestjs-i18n';
import * as nodemailer from 'nodemailer';
import { Transporter } from 'nodemailer';

@Injectable()
export class MailService implements OnModuleInit {
  private readonly logger = new Logger(MailService.name);
  private transporter: Transporter | null = null;

  constructor(
    private readonly configService: ConfigService,
    private i18n: I18nService,
  ) {}

  onModuleInit(): void {
    const host = this.configService.get<string>('mail.host');
    const port = this.configService.get<number>('mail.port');
    const user = this.configService.get<string>('mail.user');
    const password = this.configService.get<string>('mail.password');

    if (!host || !port || !user || !password) {
      this.logger.warn(
        'Email configuration is incomplete. Email service will be disabled.',
      );
      return;
    }

    this.transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: {
        user,
        pass: password,
      },
    });

    this.logger.log('Email service initialized');
  }

  async sendVerificationEmail(
    email: string,
    code: string,
    name: string = 'User',
    verifyUrl: string,
  ): Promise<void> {
    if (!this.transporter) {
      this.logger.error('Email transporter not initialized');
      return;
    }

    const fromEmail =
      this.configService.get<string>('mail.from') ?? 'noreply@example.com';

    try {
      await this.transporter.sendMail({
        from: fromEmail,
        to: email,
        subject: 'Verify Your Email Address',
        html: `
          <h1>Welcome ${name ?? 'User'}!</h1>
          <p>Thank you for registering. Please verify your email address by clicking the link below:</p>
          <a href="${verifyUrl}">Verify Email</a>
          <p>Or use this code: <strong>${code}</strong></p>
          <p>This code will expire in 24 hours.</p>
        `,
      });
      this.logger.log(`Verification email sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send verification email to ${email}:`,
        error,
      );
      throw error;
    }
  }

  async sendEmailChangeVerification(
    email: string,
    code: string,
    lang: string = 'en',
  ): Promise<void> {
    if (!this.transporter) {
      this.logger.error('Email transporter not initialized');
      return;
    }

    const subject = this.i18n.translate('mail.email_change.subject', {
      lang,
    });
    const body = this.i18n.translate('mail.email_change.body', {
      lang,
      args: { code },
    });

    const fromEmail =
      this.configService.get<string>('mail.from') ?? 'noreply@example.com';

    try {
      await this.transporter.sendMail({
        from: fromEmail,
        to: email,
        subject: subject,
        html: `
          <h1>Hello ${name ?? 'User'}</h1>
          <p>You requested to reset your password. Click the link below to reset it:</p>
          <p>Or use this code: <strong>${code}</strong></p>
          <p>This code will expire in 1 hour.</p>
          <p>If you didn't request this, please ignore this email.</p>
        `,
      });
      this.logger.log(`Password reset email sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send password reset email to ${email}:`,
        error,
      );
      throw error;
    }
  }

  async sendPasswordResetEmail(
    email: string,
    code: string,
    name: string,
    resetUrl: string,
  ): Promise<void> {
    if (!this.transporter) {
      this.logger.error('Email transporter not initialized');
      return;
    }

    const fromEmail =
      this.configService.get<string>('mail.from') ?? 'noreply@example.com';

    try {
      await this.transporter.sendMail({
        from: fromEmail,
        to: email,
        subject: 'Password Reset Request',
        html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h1>Hello ${name}</h1>
          <p>You requested to reset your password. Choose one of these methods:</p>
          
          <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h2 style="margin-top: 0;">🔗 Option 1: Click the Link</h2>
            <p>
              <a href="${resetUrl}" 
                 style="background: #007bff; color: white; padding: 12px 24px; 
                        text-decoration: none; border-radius: 4px; display: inline-block;">
                Reset Password Now
              </a>
            </p>
          </div>
          
          <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h2 style="margin-top: 0;">🔢 Option 2: Enter This Code</h2>
            <div style="background: white; padding: 20px; text-align: center; 
                        border-radius: 4px; margin: 10px 0;">
              <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; 
                          font-family: 'Courier New', monospace; color: #007bff;">
                ${code}
              </div>
            </div>
          </div>
          
          <p style="color: #666; font-size: 14px; margin-top: 30px;">
            ⏱️ This code expires in <strong>30 minutes</strong>.<br>
            🔒 If you didn't request this, please ignore this email.
          </p>
        </div>
      `,
      });
      this.logger.log(`Password reset email sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send password reset email to ${email}:`,
        error,
      );
      throw error;
    }
  }

  async send2FACode(email: string, name: string, code: string): Promise<void> {
    if (!this.transporter) {
      this.logger.error('Email transporter not initialized');
      return;
    }

    const fromEmail =
      this.configService.get<string>('mail.from') ?? 'noreply@example.com';

    try {
      await this.transporter.sendMail({
        from: fromEmail,
        to: email,
        subject: 'Two-Factor Authentication Code',
        html: `
          <h1>Hello ${name}</h1>
          <p>Your two-factor authentication code is:</p>
          <h2>${code}</h2>
          <p>This code will expire in 10 minutes.</p>
        `,
      });
      this.logger.log(`2FA code sent to ${email}`);
    } catch (error) {
      this.logger.error(`Failed to send 2FA code to ${email}:`, error);
      throw error;
    }
  }

  async sendEmail(options: {
    to: string;
    subject: string;
    html: string;
    from?: string;
  }): Promise<void> {
    if (!this.transporter) {
      this.logger.error('Email transporter not initialized');
      return;
    }

    const fromEmail =
      options.from ??
      this.configService.get<string>('mail.from') ??
      'noreply@example.com';

    try {
      await this.transporter.sendMail({
        from: fromEmail,
        to: options.to,
        subject: options.subject,
        html: options.html,
      });
      this.logger.log(`Email sent to ${options.to}`);
    } catch (error) {
      this.logger.error(`Failed to send email to ${options.to}:`, error);
      throw error;
    }
  }

  isConfigured(): boolean {
    return this.transporter !== null;
  }
}
