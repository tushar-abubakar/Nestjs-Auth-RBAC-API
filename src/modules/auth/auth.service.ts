import { AppCacheService } from '@/cache/cache.service';
import { DurationBreakdown, DurationResult } from '@/common/types/common.type';
import { JwtPayload, TokenType } from '@/common/types/jwt.type';
import { MailService } from '@/modules/mail/mail.service';
import { PrismaService } from '@/prisma/prisma.service';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { hash, verify } from 'argon2';
import { randomBytes } from 'crypto';
import { VerificationType } from 'generated/prisma/client';
import ms, { StringValue } from 'ms';
import { I18nService } from 'nestjs-i18n';
import { TwoFactorService } from '../two-factor/two-factor.service';
import {
  ForgotPasswordDto,
  LoginDto,
  RefreshTokenDto,
  RegisterDto,
  SetNewPasswordDto,
  Verify2FADto,
  VerifyEmailDto,
  VerifyResetCodeDto,
} from './dto/auth.dto';
import {
  AuthResponse,
  AuthStatus,
  EmailResendResponse,
  PasswordResetOtpResponse,
  VerifyResetResponse,
} from './types/auth-user.type';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly i18n: I18nService,
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
    private readonly mailService: MailService,
    private readonly cache: AppCacheService,
    private readonly twoFactorService: TwoFactorService,
  ) {}

  // ============================================================================
  // REGISTRATION
  // ============================================================================

  /**
   * Creates a new user account and initiates the email-verification flow.
   *
   * Steps:
   *  1. Assert email and username uniqueness.
   *  2. Resolve the default USER role.
   *  3. Persist the user with a hashed password.
   *  4. If email verification is required, generate a 6-digit OTP + URL token,
   *     persist the verification record, send the verification email, and return
   *     an EMAIL_VERIFICATION_REQUIRED challenge.
   *  5. Otherwise (verification disabled) create an auth session immediately
   *     and return AUTHENTICATED tokens.
   *
   * @throws ConflictException   Email or username already in use.
   * @throws NotFoundException   Default USER role does not exist in DB.
   */
  async register(
    dto: RegisterDto,
    userAgent: string,
    ipAddress: string,
  ): Promise<AuthResponse> {
    const { name, username, email, password } = dto;

    const existingEmail = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });
    if (existingEmail) {
      throw new ConflictException(
        this.i18n.translate('auth.errors.emailAlreadyExists'),
      );
    }

    let finalUsername = username;
    if (!finalUsername) {
      finalUsername = await this.deriveUniqueUsernameFromEmail(email);
    } else {
      const existingUsername = await this.prisma.user.findUnique({
        where: { username: finalUsername },
        select: { id: true },
      });
      if (existingUsername) {
        throw new ConflictException(
          this.i18n.translate('auth.errors.usernameAlreadyExists'),
        );
      }
    }

    const userRole = await this.prisma.role.findUnique({
      where: { code: 'USER' },
      select: { id: true },
    });
    if (!userRole) {
      throw new NotFoundException(
        this.i18n.translate('auth.errors.defaultRoleNotFound'),
      );
    }

    const requireEmailVerification = true;
    const user = await this.prisma.user.create({
      data: {
        name,
        username: finalUsername,
        email,
        password: await hash(password),
        roleId: userRole.id,
        isEmailVerified: !requireEmailVerification,
        preferences: { create: {} },
      },
      include: { preferences: true },
    });

    if (!user.isEmailVerified) {
      const urlToken = this.generateUrlToken();
      const { otp } = await this.createVerificationCode(
        user.id,
        VerificationType.EMAIL_VERIFICATION,
        1,
        1440,
        urlToken,
      );

      const {
        token: verificationToken,
        expiresAt: verificationTokenExpiresAt,
      } = this.signTokenWithExpiry(
        { sub: user.id, email: user.email, type: TokenType.EMAIL_VERIFICATION },
        '24h',
      );

      await this.applyEmailRateLimits(user.id, ipAddress);
      await this.dispatchMail(
        VerificationType.EMAIL_VERIFICATION,
        user.email,
        user.name,
        otp,
        urlToken,
      );

      const { waitSeconds: retryAfterSeconds } = this.calcRetryDelay(
        new Date(),
        0,
      );

      return {
        userId: user.id,
        status: AuthStatus.EMAIL_VERIFICATION_REQUIRED,
        challenge: {
          verificationToken,
          verificationTokenExpiresAt,
          retryAfterSeconds,
        },
        message: await this.i18n.translate('auth.success.registered'),
      };
    }

    return this.buildAuthResponse(
      user.id,
      user.email,
      null, // email verification disabled — no 2FA possible yet at registration
      userAgent,
      ipAddress,
      false,
      this.i18n.translate('auth.success.registered'),
    );
  }

  // ============================================================================
  // LOGIN
  // ============================================================================

  /**
   * Authenticates a user with email/username and password.
   *
   * Steps:
   *  1. Enforce a sliding-window rate limit (5 attempts / 15 min) keyed on the
   *     identifier to slow credential-stuffing attacks.
   *  2. Look up the user and verify the password; increment the counter on any
   *     failure so the window slides even across different fields.
   *  3. Gate on account-active and email-verified flags.
   *  4. If 2FA is enabled, return a short-lived TWO_FACTOR challenge token.
   *  5. Otherwise create a full auth session and return tokens.
   *
   * @throws BadRequestException    Rate limit exceeded.
   * @throws UnauthorizedException  Bad credentials.
   * @throws ForbiddenException     Account inactive or email unverified.
   */
  async login(
    dto: LoginDto,
    userAgent: string,
    ipAddress: string,
  ): Promise<AuthResponse> {
    const rateLimitKey = `login:attempts:${dto.emailOrUsername}`;
    const maxAttempts = 5;
    const windowSeconds = 900; // 15 min

    const attempts = (await this.cache.get<number>(rateLimitKey)) ?? 0;
    if (attempts >= maxAttempts) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.tooManyLoginAttempts'),
      );
    }

    const email = dto.emailOrUsername.toLowerCase();
    const user = await this.prisma.user.findFirst({
      where: { OR: [{ email }, { username: dto.emailOrUsername }] },
      include: { preferences: true },
    });

    if (!user) {
      await this.cache.increment(rateLimitKey, windowSeconds);
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.invalidCredentials'),
      );
    }

    const passwordValid = await verify(user.password, dto.password);
    if (!passwordValid) {
      await this.cache.increment(rateLimitKey, windowSeconds);
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.invalidCredentials'),
      );
    }

    if (!user.isActive) {
      throw new ForbiddenException(
        this.i18n.translate('auth.errors.accountInactive'),
      );
    }

    await this.cache.del(rateLimitKey);

    if (!user.isEmailVerified) {
      throw new ForbiddenException(
        this.i18n.translate('auth.errors.emailNotVerified'),
      );
    }

    return this.buildAuthResponse(
      user.id,
      user.email,
      user.preferences,
      userAgent,
      ipAddress,
      dto.remember ?? false,
      this.i18n.translate('auth.success.loggedIn'),
    );
  }

  // ============================================================================
  // EMAIL VERIFICATION — OTP PATH (POST /auth/email/verify-otp)
  // ============================================================================

  /**
   * Verifies the user's email address using the 6-digit OTP they received.
   *
   * @throws BadRequestException   Rate limit exceeded, invalid, or expired code.
   * @throws ForbiddenException    Account inactive or email already verified.
   */
  async verifyEmailOtpAndLogin(
    dto: VerifyEmailDto,
    userId: string,
    userAgent: string,
    ipAddress: string,
  ): Promise<AuthResponse> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { preferences: true },
    });

    if (!user || !user.isActive) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalidVerificationCode'),
      );
    }

    if (user.isEmailVerified) {
      throw new ForbiddenException(
        this.i18n.translate('auth.errors.emailAlreadyVerified'),
      );
    }

    await this.verifyEmailOtp(
      userId,
      dto.code,
      VerificationType.EMAIL_VERIFICATION,
    );

    await this.prisma.user.update({
      where: { id: user.id },
      data: { isEmailVerified: true },
    });

    return this.buildAuthResponse(
      user.id,
      user.email,
      user.preferences,
      userAgent,
      ipAddress,
      false,
      this.i18n.translate('auth.success.emailVerified'),
    );
  }

  // ============================================================================
  // EMAIL VERIFICATION — LINK PATH (GET /auth/email/verify-link)
  // ============================================================================

  /**
   * Verifies the user's email address via the magic link they received.
   *
   * Rate limiting (no JWT guard — the urlToken is the identity):
   *  • Per token : 5 failed attempts / 15 min
   *  • Per IP    : 10 failed attempts / 15 min
   *
   * @throws BadRequestException    Rate limit exceeded, missing params, invalid
   *                                link, already-verified, or wrong code.
   * @throws UnauthorizedException  Account inactive.
   */
  async verifyEmailLinkAndLogin(
    urlToken: string,
    code: string,
    userAgent: string,
    ipAddress: string,
  ): Promise<AuthResponse> {
    if (!urlToken || !code) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.missingTokenOrCode'),
      );
    }

    const tokenRateKey = `verify-link:attempts:token:${urlToken}`;
    const ipRateKey = `verify-link:attempts:ip:${ipAddress}`;
    const windowSeconds = 900; // 15 min

    const [tokenAttempts, ipAttempts] = await Promise.all([
      this.cache.get<number>(tokenRateKey).then((v) => v ?? 0),
      this.cache.get<number>(ipRateKey).then((v) => v ?? 0),
    ]);

    if (tokenAttempts >= 5) {
      const waitMinutes = Math.ceil((await this.cache.ttl(tokenRateKey)) / 60);
      throw new BadRequestException(
        this.i18n.translate('auth.errors.verificationRateLimitExceeded', {
          args: { minutes: waitMinutes },
        }),
      );
    }

    if (ipAttempts >= 10) {
      const waitMinutes = Math.ceil((await this.cache.ttl(ipRateKey)) / 60);
      throw new BadRequestException(
        this.i18n.translate('auth.errors.verificationRateLimitExceeded', {
          args: { minutes: waitMinutes },
        }),
      );
    }

    const record = await this.prisma.verificationCode.findUnique({
      where: { urlToken },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            name: true,
            isActive: true,
            isEmailVerified: true,
            preferences: { select: { enable2FA: true, twoFactorSecret: true } },
          },
        },
      },
    });

    if (!record) {
      await Promise.all([
        this.cache.increment(tokenRateKey, windowSeconds),
        this.cache.increment(ipRateKey, windowSeconds),
      ]);
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalidOrExpiredLink'),
      );
    }

    const { user } = record;

    if (!user.isActive) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.accountInactive'),
      );
    }

    if (user.isEmailVerified) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.emailAlreadyVerified'),
      );
    }

    if (record.expiresAt < new Date()) {
      await this.prisma.verificationCode.delete({ where: { id: record.id } });
      throw new BadRequestException(
        this.i18n.translate('auth.errors.verificationLinkExpired'),
      );
    }

    const codeMatches = await verify(record.code, code);
    if (!codeMatches) {
      await Promise.all([
        this.cache.increment(tokenRateKey, windowSeconds),
        this.cache.increment(ipRateKey, windowSeconds),
      ]);
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalidVerificationCode'),
      );
    }

    await this.prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: user.id },
        data: { isEmailVerified: true },
      });
      await tx.verificationCode.delete({ where: { id: record.id } });
    });

    await Promise.all([
      this.cache.del(tokenRateKey),
      this.cache.del(ipRateKey),
    ]);

    return this.buildAuthResponse(
      user.id,
      user.email,
      user.preferences,
      userAgent,
      ipAddress,
      false,
      this.i18n.translate('auth.success.emailVerified'),
    );
  }

  // ============================================================================
  // TWO-FACTOR AUTHENTICATION
  // ============================================================================

  /**
   * Completes the 2FA step after a successful login or email-verification.
   *
   * @throws BadRequestException  2FA not configured or TOTP code invalid.
   */
  async completeTwoFactorLogin(
    dto: Verify2FADto,
    userId: string,
    ipAddress: string,
    userAgent: string,
    remember: boolean = false,
  ): Promise<AuthResponse> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { preferences: true },
    });

    if (
      !user ||
      !user.preferences?.enable2FA ||
      !user.preferences.twoFactorSecret
    ) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalid2faCode'),
      );
    }

    const isValid = this.twoFactorService.verifyToken(
      dto.code,
      user.preferences.twoFactorSecret,
    );

    if (!isValid) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalid2faCode'),
      );
    }

    return this.buildAuthResponse(
      user.id,
      user.email,
      null, // 2FA already verified — skip 2FA re-check
      userAgent,
      ipAddress,
      remember,
      this.i18n.translate('auth.success.loggedInWith2fa'),
    );
  }

  // ============================================================================
  // TOKEN REFRESH
  // ============================================================================

  /**
   * Rotates a refresh token into a fresh access + refresh token pair.
   *
   * @throws UnauthorizedException  Token invalid, expired, wrong type, or session not found.
   * @throws ForbiddenException     User account is now inactive.
   */
  async rotateRefreshToken(
    dto: RefreshTokenDto,
    userAgent: string,
    ipAddress: string,
  ): Promise<AuthResponse> {
    try {
      const payload = this.jwtService.verify<JwtPayload>(dto.refreshToken);

      if (payload.type !== TokenType.REFRESH || !payload.sessionId) {
        throw new UnauthorizedException(
          this.i18n.translate('auth.errors.invalidCredentials'),
        );
      }

      const session = await this.prisma.session.findUnique({
        where: { id: payload.sessionId },
        include: { user: true },
      });

      if (!session || session.expiredAt < new Date()) {
        throw new UnauthorizedException(
          this.i18n.translate('auth.errors.invalidCredentials'),
        );
      }

      if (!session.user.isActive) {
        throw new ForbiddenException(
          this.i18n.translate('auth.errors.accountInactive'),
        );
      }

      const remember = payload.remember ?? false;

      await this.prisma.session.delete({ where: { id: session.id } });

      return this.buildAuthResponse(
        session.userId,
        session.user.email,
        null, // token rotation — 2FA already proven, skip re-check
        userAgent,
        ipAddress,
        remember,
        this.i18n.translate('auth.success.tokenRefreshed'),
      );
    } catch {
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.invalidCredentials'),
      );
    }
  }

  // ============================================================================
  // PASSWORD RESET — STEP 1: INITIATE (POST /auth/password/forgot)
  // ============================================================================

  /**
   * Initiates the password-reset flow for a given email/username.
   *
   * Security: IP-rate-limit + timing-safe fake responses for unknown users.
   *
   * @throws BadRequestException  IP rate limit exceeded.
   */
  async initiatePasswordReset(
    dto: ForgotPasswordDto,
    ipAddress: string,
  ): Promise<PasswordResetOtpResponse> {
    const startTime = Date.now();

    const ipKey = `password-reset:ip:${ipAddress}`;
    const ipAttempts = (await this.cache.get<number>(ipKey)) ?? 0;
    if (ipAttempts >= 10) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.tooManyPasswordResetRequestsFromIp'),
      );
    }
    await this.cache.increment(ipKey, 3600);

    const identifier = dto.emailOrUsername.toLowerCase();
    const user = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: identifier }, { username: dto.emailOrUsername }],
        isActive: true,
      },
    });

    const genericMessage = this.i18n.translate(
      'auth.success.passwordResetEmailSent',
    );

    if (!user) {
      const elapsed = Date.now() - startTime;
      if (elapsed < 200) await new Promise((r) => setTimeout(r, 200 - elapsed));

      this.logger.warn(
        `Password-reset attempt for non-existent identifier: ${dto.emailOrUsername}`,
      );

      return this.buildFakePasswordResetResponse(
        'fake-user-id',
        genericMessage,
      );
    }

    await this.applyEmailRateLimits(user.id, ipAddress, 'PASSWORD_RESET');

    const result = await this.dispatchPasswordResetCode(user);

    return { ...result, message: genericMessage };
  }

  // ============================================================================
  // PASSWORD RESET — STEP 1 (RESEND): POST /auth/password/resend-otp
  // ============================================================================

  /**
   * Resends a password-reset OTP for a user who already holds a
   * PASSWORD_RESET_VERIFICATION token (guard-protected endpoint).
   *
   * @throws BadRequestException    Rate limit exceeded.
   * @throws UnauthorizedException  User not found.
   * @throws ForbiddenException     Account inactive.
   */
  async resendPasswordResetOtp(
    userId: string,
    isFakeUser: boolean = false,
    ipAddress?: string,
  ): Promise<PasswordResetOtpResponse> {
    const genericMessage = this.i18n.translate(
      'auth.success.passwordResetEmailSent',
    );

    if (isFakeUser) {
      return this.buildFakePasswordResetResponse(userId, genericMessage);
    }

    const user = await this.prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
      this.logger.error(
        `resendPasswordResetOtp: real userId not found in DB — ${userId}`,
      );
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.invalidCredentials'),
      );
    }

    if (!user.isActive) {
      throw new ForbiddenException(
        this.i18n.translate('auth.errors.accountInactive'),
      );
    }

    await this.applyEmailRateLimits(userId, ipAddress, 'PASSWORD_RESET');

    const result = await this.dispatchPasswordResetCode(user);

    return { ...result, message: genericMessage };
  }

  // ============================================================================
  // EMAIL VERIFICATION — RESEND OTP (POST /auth/email/resend-otp)
  // ============================================================================

  /**
   * Resends an email-verification OTP for a user who already holds an
   * EMAIL_VERIFICATION token (guard-protected endpoint).
   *
   * @throws BadRequestException   Rate limit exceeded or email already verified.
   * @throws UnauthorizedException User not found.
   * @throws ForbiddenException    Account inactive.
   */
  async resendEmailVerificationOtp(
    userId: string,
    ipAddress?: string,
  ): Promise<EmailResendResponse> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
      this.logger.error(
        `resendEmailVerificationOtp: real userId not found in DB — ${userId}`,
      );
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.invalidCredentials'),
      );
    }

    if (!user.isActive) {
      throw new ForbiddenException(
        this.i18n.translate('auth.errors.accountInactive'),
      );
    }

    if (user.isEmailVerified) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.emailAlreadyVerified'),
      );
    }

    await this.applyEmailRateLimits(
      userId,
      ipAddress,
      VerificationType.EMAIL_VERIFICATION,
    );

    const { nextAttemptCount, dailyMaxAttempts } =
      await this.resolveResendAttemptCount(
        userId,
        VerificationType.EMAIL_VERIFICATION,
        7,
      );

    const urlToken = this.generateUrlToken();
    const { otp } = await this.createVerificationCode(
      user.id,
      VerificationType.EMAIL_VERIFICATION,
      nextAttemptCount,
      1440,
      urlToken,
    );

    await this.dispatchMail(
      VerificationType.EMAIL_VERIFICATION,
      user.email,
      user.name,
      otp,
      urlToken,
    );

    const { waitSeconds: nextRetryIn } = this.calcRetryDelay(
      new Date(),
      nextAttemptCount,
    );
    const attemptsRemaining = dailyMaxAttempts - nextAttemptCount;

    return {
      retryAfterSeconds: attemptsRemaining > 0 ? nextRetryIn : 0,
      attemptsRemaining: Math.max(attemptsRemaining, 0),
      message: this.i18n.translate('auth.success.verificationEmailSent'),
    };
  }

  // ============================================================================
  // PASSWORD RESET — STEP 2A: VERIFY OTP (POST /auth/password/verify-otp)
  // ============================================================================

  /**
   * Verifies the 6-digit OTP from the password-reset email (manual entry path).
   *
   * @throws BadRequestException    Invalid or expired code.
   * @throws UnauthorizedException  Inactive account or stale secret.
   */
  async verifyPasswordResetOtp(
    dto: VerifyResetCodeDto,
    userId: string,
    secret: string,
    isFakeUser: boolean = false,
  ): Promise<VerifyResetResponse> {
    if (isFakeUser) {
      this.logger.warn(`verifyPasswordResetOtp: fake user — ${userId}`);
      await this.simulateDbDelay();
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalidResetCode'),
      );
    }

    const user = await this.prisma.user.findUnique({ where: { id: userId } });

    if (!user || !user.isActive) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalidResetCode'),
      );
    }

    if (!user.passwordResetSecret || user.passwordResetSecret !== secret) {
      this.logger.warn(
        `verifyPasswordResetOtp: stale secret for user ${userId} — token was invalidated`,
      );
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.resetTokenInvalidated'),
      );
    }

    const record = await this.prisma.verificationCode.findUnique({
      where: {
        userId_type: { userId: user.id, type: VerificationType.PASSWORD_RESET },
      },
    });

    if (!record) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalidResetCode'),
      );
    }

    if (record.expiresAt < new Date()) {
      await this.prisma.verificationCode.delete({ where: { id: record.id } });
      throw new BadRequestException(
        this.i18n.translate('auth.errors.resetCodeExpired'),
      );
    }

    const codeValid = await verify(record.code, dto.code);
    if (!codeValid) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalidResetCode'),
      );
    }

    return this.rotateResetSecretAndIssueToken(user.id, user.email, record.id);
  }

  // ============================================================================
  // PASSWORD RESET — STEP 2B: VERIFY LINK (GET /auth/password/verify-link)
  // ============================================================================

  /**
   * Verifies the password-reset link the user clicked in their email.
   *
   * @throws BadRequestException    Missing params, expired link, or wrong code.
   * @throws UnauthorizedException  Account inactive.
   */
  async verifyPasswordResetLink(
    urlToken: string,
    code: string,
  ): Promise<VerifyResetResponse> {
    if (!urlToken || !code) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.missingTokenOrCode'),
      );
    }

    const record = await this.prisma.verificationCode.findUnique({
      where: { urlToken },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            isActive: true,
            passwordResetSecret: true,
          },
        },
      },
    });

    if (!record?.user) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalidOrExpiredLink'),
      );
    }

    if (record.expiresAt < new Date()) {
      await this.prisma.verificationCode.delete({ where: { id: record.id } });
      throw new BadRequestException(
        this.i18n.translate('auth.errors.resetLinkExpired'),
      );
    }

    if (!record.user.isActive) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.accountInactive'),
      );
    }

    const codeValid = await verify(record.code, code);
    if (!codeValid) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalidResetCode'),
      );
    }

    return this.rotateResetSecretAndIssueToken(
      record.user.id,
      record.user.email,
      record.id,
    );
  }

  // ============================================================================
  // PASSWORD RESET — STEP 3: SET NEW PASSWORD (POST /auth/password/reset)
  // ============================================================================

  /**
   * Sets a new password for the user who holds a valid PASSWORD_RESET token.
   *
   * @throws UnauthorizedException  User not found, inactive, or stale secret.
   */
  async resetPassword(
    dto: SetNewPasswordDto,
    userId: string,
    secret: string,
    userAgent: string,
    ipAddress: string,
  ): Promise<AuthResponse> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { preferences: true },
    });

    if (!user || !user.isActive) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.invalidCredentials'),
      );
    }

    if (!user.passwordResetSecret || user.passwordResetSecret !== secret) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.resetTokenInvalidated'),
      );
    }

    await this.prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: user.id },
        data: {
          password: await hash(dto.newPassword),
          passwordResetSecret: null,
          isEmailVerified: true,
        },
      });

      // Delete OTP records for both flows: the reset code just consumed and any outstanding email-verification code
      await tx.verificationCode.deleteMany({
        where: {
          userId: user.id,
          type: {
            in: [
              VerificationType.PASSWORD_RESET,
              VerificationType.EMAIL_VERIFICATION,
            ],
          },
        },
      });

      if (dto.deleteOtherSessions) {
        await tx.session.deleteMany({ where: { userId: user.id } });
      }
    });

    // Purge email-verification cache keys
    await Promise.all([
      this.cache.del(
        `verify:attempts:${user.id}:${VerificationType.EMAIL_VERIFICATION}`,
      ),
      this.cache.del(
        `resend:attempts:${user.id}:${VerificationType.EMAIL_VERIFICATION}`,
      ),
      this.cache.del(`email-send:user:${user.id}`),
    ]);

    return this.buildAuthResponse(
      user.id,
      user.email,
      user.preferences,
      userAgent,
      ipAddress,
      false,
      this.i18n.translate('auth.success.passwordReset'),
    );
  }

  // ============================================================================
  // PRIVATE — SHARED RESPONSE BUILDERS
  // ============================================================================

  /**
   * Builds the appropriate post-authentication AuthResponse.
   *
   * Used after login, email verification, 2FA completion, and password reset.
   * If 2FA is active → TWO_FACTOR_REQUIRED challenge.
   * Otherwise        → AUTHENTICATED with session tokens.
   */
  private async buildAuthResponse(
    userId: string,
    email: string,
    preferences:
      | { enable2FA?: boolean | null; twoFactorSecret?: string | null }
      | null
      | undefined,
    userAgent: string,
    ipAddress: string,
    remember: boolean = false,
    successMessage?: string,
  ): Promise<AuthResponse> {
    if (preferences?.enable2FA && preferences.twoFactorSecret) {
      // Signs a short-lived TWO_FACTOR token and wraps it in a TWO_FACTOR_REQUIRED AuthResponse.
      const expiry =
        this.config.get<StringValue>('jwt.twoFactorExpiresIn') || '10m';

      const { token: twoFactorToken, expiresAt: twoFactorTokenExpiresAt } =
        this.signTokenWithExpiry(
          { sub: userId, email, type: TokenType.TWO_FACTOR, remember },
          expiry,
        );

      return {
        userId,
        status: AuthStatus.TWO_FACTOR_REQUIRED,
        challenge: { twoFactorToken, twoFactorTokenExpiresAt },
        message: this.i18n.translate('auth.success.emailVerified'),
      };
    }

    const session = await this.createAuthSession(
      userId,
      email,
      userAgent,
      ipAddress,
      remember,
    );

    return {
      userId,
      status: AuthStatus.AUTHENTICATED,
      tokens: session,
      message: successMessage ?? this.i18n.translate('auth.success.loggedIn'),
    };
  }

  // ============================================================================
  // PRIVATE — CALENDAR DAY HELPER
  // ============================================================================

  /** Returns true when two dates fall on the same calendar day (local time). */
  private isSameCalendarDay(a: Date, b: Date): boolean {
    return (
      a.getFullYear() === b.getFullYear() &&
      a.getMonth() === b.getMonth() &&
      a.getDate() === b.getDate()
    );
  }

  // ============================================================================
  // PRIVATE — PASSWORD RESET SECRET ROTATION (shared by verify-otp + verify-link)
  // ============================================================================

  /**
   * Atomically deletes the OTP record, rotates the `passwordResetSecret`, and
   * issues a short-lived PASSWORD_RESET token.
   *
   * Extracted to eliminate the identical block that previously existed in both
   * `verifyPasswordResetOtp` and `verifyPasswordResetLink`.
   */
  private async rotateResetSecretAndIssueToken(
    userId: string,
    email: string,
    recordId: string,
  ): Promise<VerifyResetResponse> {
    const newSecret = this.generateResetSecret();

    await this.prisma.$transaction(async (tx) => {
      await tx.verificationCode.delete({ where: { id: recordId } });
      await tx.user.update({
        where: { id: userId },
        data: { passwordResetSecret: newSecret },
      });
    });

    const { token: resetToken, expiresAt: resetTokenExpiresAt } =
      this.signTokenWithExpiry(
        {
          sub: userId,
          email,
          type: TokenType.PASSWORD_RESET,
          secret: newSecret,
        },
        '10m',
      );

    return {
      resetToken,
      resetTokenExpiresAt,
      message: this.i18n.translate('auth.success.resetCodeVerified'),
    };
  }

  // ============================================================================
  // PRIVATE — SHARED OTP VERIFICATION CORE
  // ============================================================================

  /**
   * Core OTP verification logic shared by the email-verification OTP path.
   * Enforces two independent rate-limit layers then verifies the hash.
   *
   * On success: deletes the DB record and clears the cache counter atomically.
   * On failure: increments both counters and returns a contextual error.
   *
   * @throws BadRequestException  Rate limit exceeded, code expired, or wrong code.
   */
  private async verifyEmailOtp(
    userId: string,
    enteredCode: string,
    type: VerificationType,
  ): Promise<void> {
    const cacheKey = `verify:attempts:${userId}:${type}`;
    const cacheAttempts = (await this.cache.get<number>(cacheKey)) ?? 0;
    const maxCacheAttempts = 5;
    const cacheTTL = 900; // 15 min

    if (cacheAttempts >= maxCacheAttempts) {
      const waitMinutes = Math.ceil((await this.cache.ttl(cacheKey)) / 60);
      throw new BadRequestException(
        this.i18n.translate('auth.errors.verificationRateLimitExceeded', {
          args: { minutes: waitMinutes },
        }),
      );
    }

    const record = await this.prisma.verificationCode.findUnique({
      where: { userId_type: { userId, type } },
    });

    if (!record) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalidVerificationCode'),
      );
    }

    const now = new Date();
    if (record.expiresAt < now) {
      await this.prisma.verificationCode.delete({ where: { id: record.id } });
      throw new BadRequestException(
        this.i18n.translate('auth.errors.verificationCodeExpired'),
      );
    }

    const dailyMax = this.config.get<number>(
      'verification.dailyMaxVerifyAttempts',
      10,
    );

    const isSameDay = this.isSameCalendarDay(now, record.lastSentAt);
    const currentAttempts = isSameDay ? record.attempts : 0;

    if (isSameDay && currentAttempts >= dailyMax) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.dailyVerifyAttemptsExceeded', {
          args: { max: dailyMax, resetsAt: 'midnight' },
        }),
      );
    }

    const codeValid = await verify(record.code, enteredCode);

    if (!codeValid) {
      const newCount = isSameDay ? currentAttempts + 1 : 1;

      await Promise.all([
        this.prisma.verificationCode.update({
          where: { id: record.id },
          data: { attempts: newCount, lastSentAt: now },
        }),
        this.cache.increment(cacheKey, cacheTTL),
      ]);

      const remaining = dailyMax - newCount;

      if (remaining <= 0) {
        throw new BadRequestException(
          this.i18n.translate('auth.errors.dailyVerifyAttemptsExceeded', {
            args: { max: dailyMax, resetsAt: 'midnight' },
          }),
        );
      }

      if (remaining <= 2) {
        throw new BadRequestException(
          this.i18n.translate('auth.errors.invalidCodeFinalWarning', {
            args: { remaining },
          }),
        );
      }

      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalidCodeWithAttemptsRemaining', {
          args: { remaining },
        }),
      );
    }

    await this.prisma.$transaction(async (tx) => {
      await tx.verificationCode.delete({ where: { id: record.id } });
      await this.cache.del(cacheKey);
    });
  }

  // ============================================================================
  // PRIVATE — PASSWORD RESET CODE DISPATCH (shared by initiate + resend)
  // ============================================================================

  /**
   * Generates a new OTP, rotates the `passwordResetSecret`, sends the reset
   * email, and returns the signed verification token.
   *
   * Applies DB-side daily limits and exponential-backoff between sends.
   */
  private async dispatchPasswordResetCode(user: {
    id: string;
    email: string;
    name: string;
  }): Promise<{
    verificationToken: string;
    verificationTokenExpiresAt: string;
    retryAfterSeconds: number;
    attemptsRemaining: number;
  }> {
    const existingRecord = await this.prisma.verificationCode.findUnique({
      where: {
        userId_type: { userId: user.id, type: VerificationType.PASSWORD_RESET },
      },
    });

    const dailyMax = this.config.get<number>(
      'verification.dailyMaxPasswordResetAttempts',
      5,
    );

    let currentAttempts = 1;

    if (existingRecord) {
      const now = new Date();
      const isSameDay = this.isSameCalendarDay(now, existingRecord.lastSentAt);

      if (isSameDay) {
        currentAttempts = existingRecord.attempts;

        if (currentAttempts >= dailyMax) {
          throw new BadRequestException(
            this.i18n.translate('auth.errors.dailyPasswordResetLimitReached', {
              args: { max: dailyMax },
            }),
          );
        }

        const { waitSeconds, waitFormatted } = this.calcRetryDelay(
          existingRecord.lastSentAt,
          currentAttempts,
        );

        if (waitSeconds > 0) {
          const attemptsRemaining = dailyMax - currentAttempts;
          throw new BadRequestException({
            message: this.i18n.translate('auth.errors.passwordResetTooSoon', {
              args: { time: waitFormatted, attemptsRemaining },
            }),
            retryAfterSeconds: waitSeconds,
            attemptsRemaining,
            statusCode: HttpStatus.BAD_REQUEST,
          });
        }

        currentAttempts += 1;
      } else {
        currentAttempts = 1;
      }
    }

    const newSecret = this.generateResetSecret();
    const urlToken = this.generateUrlToken();

    const { otp } = await this.createVerificationCode(
      user.id,
      VerificationType.PASSWORD_RESET,
      currentAttempts,
      30,
      urlToken,
    );

    await this.prisma.user.update({
      where: { id: user.id },
      data: { passwordResetSecret: newSecret },
    });

    const { token: verificationToken, expiresAt: verificationTokenExpiresAt } =
      this.signTokenWithExpiry(
        {
          sub: user.id,
          email: user.email,
          type: TokenType.PASSWORD_RESET_VERIFICATION,
          secret: newSecret,
        },
        '30m',
      );

    await this.dispatchMail(
      VerificationType.PASSWORD_RESET,
      user.email,
      user.name,
      otp,
      urlToken,
    );

    const { waitSeconds: nextRetryIn } = this.calcRetryDelay(
      new Date(),
      currentAttempts,
    );
    const attemptsRemaining = dailyMax - currentAttempts;

    this.logger.log(
      `Password-reset OTP dispatched for user ${user.id} (attempt ${currentAttempts}/${dailyMax})`,
    );

    return {
      verificationToken,
      verificationTokenExpiresAt,
      retryAfterSeconds: attemptsRemaining > 0 ? nextRetryIn : 0,
      attemptsRemaining: Math.max(attemptsRemaining, 0),
    };
  }

  // ============================================================================
  // PRIVATE — UNIFIED EMAIL SEND RATE LIMITS
  // ============================================================================

  /**
   * Enforces the three shared email-send rate-limit layers used by every flow
   * that dispatches an email (register, resend email-verification, initiate/resend
   * password-reset).
   *
   * Layers enforced:
   *   • IP    : 20 emails / hr   (optional — skipped when ipAddress is undefined)
   *   • User  : 30 emails / day
   *   • Resend: 20 attempts / hr per userId+type (optional — skipped when verificationType is undefined)
   *
   * The IP and user counters share the same cache keys across all flows
   * so the limits are global — not per-flow.
   */
  private async applyEmailRateLimits(
    userId: string,
    ipAddress?: string,
    verificationType?: string,
  ): Promise<void> {
    if (ipAddress) {
      const ipKey = `email-send:ip:${ipAddress}`;
      const ipAttempts = (await this.cache.get<number>(ipKey)) ?? 0;
      if (ipAttempts >= 20) {
        throw new BadRequestException(
          this.i18n.translate('auth.errors.tooManyEmailRequestsFromIp'),
        );
      }
      await this.cache.increment(ipKey, 3600);
    }

    const userKey = `email-send:user:${userId}`;
    const userAttempts = (await this.cache.get<number>(userKey)) ?? 0;
    if (userAttempts >= 30) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.dailyEmailLimitReached'),
      );
    }
    await this.cache.increment(userKey, 86400);

    if (verificationType) {
      const resendKey = `resend:attempts:${userId}:${verificationType}`;
      const resendAttempts = await this.cache.increment(resendKey, 3600);
      if (resendAttempts > 20) {
        throw new BadRequestException(
          this.i18n.translate('auth.errors.resendLimitExceeded'),
        );
      }
    }
  }

  // ============================================================================
  // PRIVATE — FAKE PASSWORD RESET RESPONSE (initiate + resend)
  // ============================================================================

  /**
   * Returns a `PasswordResetOtpResponse` structurally indistinguishable from a
   * real response, for non-existent users — prevents user enumeration.
   */
  private async buildFakePasswordResetResponse(
    fakeUserId: string,
    message: string,
  ): Promise<PasswordResetOtpResponse> {
    this.logger.warn(
      `Password-reset fake response for fakeUserId=${fakeUserId}`,
    );

    const state = await this.fetchOrInitFakeUserState(
      fakeUserId,
      VerificationType.PASSWORD_RESET,
    );

    if (state.attempts > state.dailyMaxAttempts) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.dailyMaxAttemptsReached', {
          args: { max: state.dailyMaxAttempts },
        }),
      );
    }

    const makeFakeToken = (): { token: string; expiresAt: string } =>
      this.signTokenWithExpiry(
        {
          sub: fakeUserId,
          email: 'fake@email.com',
          type: TokenType.PASSWORD_RESET_VERIFICATION,
          secret: 'fake-secret',
          isFakeUser: true,
        },
        '30m',
      );

    const { waitSeconds, waitFormatted } = this.calcRetryDelay(
      state.lastRequestAt,
      state.attempts - 1,
    );

    if (waitSeconds > 0) {
      const attemptsRemaining = state.dailyMaxAttempts - state.attempts + 1;
      await this.simulateDbDelay();

      const { token: fakeToken, expiresAt: fakeExpiresAt } = makeFakeToken();

      throw new BadRequestException({
        message: this.i18n.translate('auth.errors.passwordResetTooSoon', {
          args: { time: waitFormatted, attemptsRemaining },
        }),
        verificationToken: fakeToken,
        verificationTokenExpiresAt: fakeExpiresAt,
        retryAfterSeconds: waitSeconds,
        attemptsRemaining,
        statusCode: HttpStatus.BAD_REQUEST,
      });
    }

    await this.simulateDbDelay();

    const { token: fakeToken, expiresAt: fakeExpiresAt } = makeFakeToken();
    const { waitSeconds: nextRetryIn } = this.calcRetryDelay(
      new Date(),
      state.attempts,
    );
    const attemptsRemaining = state.dailyMaxAttempts - state.attempts;

    return {
      verificationToken: fakeToken,
      verificationTokenExpiresAt: fakeExpiresAt,
      retryAfterSeconds: Math.max(
        attemptsRemaining > 0
          ? nextRetryIn + (Math.floor(Math.random() * 5) - 2)
          : 0,
        0,
      ),
      attemptsRemaining: Math.max(
        attemptsRemaining > 0
          ? attemptsRemaining + (Math.random() < 0.3 ? 1 : 0)
          : 0,
        0,
      ),
      message,
    };
  }

  // ============================================================================
  // PRIVATE — RESEND ATTEMPT COUNT RESOLVER
  // ============================================================================

  /**
   * Reads the current verification record to determine how many resend attempts
   * have already been made today. Enforces the daily limit and exponential
   * backoff window.
   *
   * @throws BadRequestException  Daily limit reached or too soon to resend.
   */
  private async resolveResendAttemptCount(
    userId: string,
    type: VerificationType,
    dailyMax: number,
  ): Promise<{ nextAttemptCount: number; dailyMaxAttempts: number }> {
    const existingRecord = await this.prisma.verificationCode.findUnique({
      where: { userId_type: { userId, type } },
    });

    if (!existingRecord) {
      return { nextAttemptCount: 1, dailyMaxAttempts: dailyMax };
    }

    const isSameDay = this.isSameCalendarDay(
      new Date(),
      existingRecord.lastSentAt,
    );

    if (!isSameDay) {
      return { nextAttemptCount: 1, dailyMaxAttempts: dailyMax };
    }

    const currentAttempts = existingRecord.attempts;

    if (currentAttempts >= dailyMax) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.dailyMaxAttemptsReached', {
          args: { max: dailyMax },
        }),
      );
    }

    const { waitSeconds, waitFormatted } = this.calcRetryDelay(
      existingRecord.lastSentAt,
      currentAttempts,
    );

    if (waitSeconds > 0) {
      const attemptsRemaining = dailyMax - currentAttempts;
      throw new BadRequestException({
        message: this.i18n.translate('auth.errors.resendTooSoon', {
          args: { time: waitFormatted, attemptsRemaining },
        }),
        retryAfterSeconds: waitSeconds,
        attemptsRemaining,
        statusCode: HttpStatus.BAD_REQUEST,
      } as EmailResendResponse);
    }

    return {
      nextAttemptCount: currentAttempts + 1,
      dailyMaxAttempts: dailyMax,
    };
  }

  // ============================================================================
  // PRIVATE — TOKEN & SESSION FACTORIES
  // ============================================================================

  /**
   * Signs a JWT and returns both the token string and the exact ISO 8601 expiry
   * timestamp read back from the token's own `exp` claim.
   */
  private signTokenWithExpiry(
    payload: JwtPayload,
    expiresIn?: StringValue,
  ): { token: string; expiresAt: string } {
    const resolvedExpiry =
      expiresIn ?? this.config.get<StringValue>('jwt.expiresIn') ?? '1d';

    let validExpiry = resolvedExpiry;
    const expiryMs = ms(resolvedExpiry);

    if (!expiryMs || expiryMs <= 0) {
      this.logger.debug(
        `Invalid JWT expiry "${resolvedExpiry}", falling back to 1d`,
      );
      validExpiry = '1d';
    }

    const token = this.jwtService.sign(payload, {
      expiresIn: validExpiry,
    });
    const decoded = this.jwtService.decode<JwtPayload & { exp?: number }>(
      token,
    );
    const expiresAt = new Date((decoded?.exp ?? 0) * 1000).toISOString();

    return { token, expiresAt };
  }

  /**
   * Creates a DB session and issues access + refresh tokens.
   *
   * Expiry durations:
   *  • Standard  : access 1 d / refresh 7 d
   *  • Remember  : access 30 d / refresh 60 d
   */
  private async createAuthSession(
    userId: string,
    email: string,
    userAgent: string,
    ipAddress: string,
    remember: boolean = false,
  ): Promise<{
    accessToken: string;
    accessTokenExpiresAt: string;
    refreshToken: string;
    refreshTokenExpiresAt: string;
  }> {
    const accessExpiry = remember
      ? this.config.get<StringValue>('jwt.rememberExpiresIn') || '30d'
      : this.config.get<StringValue>('jwt.expiresIn') || '1d';

    const refreshExpiry = remember
      ? this.config.get<StringValue>('jwt.refreshRememberExpiresIn') || '60d'
      : this.config.get<StringValue>('jwt.refreshExpiresIn') || '7d';

    const session = await this.prisma.session.create({
      data: {
        userId,
        userAgent,
        ipAddress,
        expiredAt: new Date(Date.now() + ms(accessExpiry)),
      },
    });

    const { token: accessToken, expiresAt: accessTokenExpiresAt } =
      this.signTokenWithExpiry(
        {
          sub: userId,
          email,
          type: TokenType.ACCESS,
          sessionId: session.id,
          remember,
        },
        accessExpiry,
      );

    const { token: refreshToken, expiresAt: refreshTokenExpiresAt } =
      this.signTokenWithExpiry(
        {
          sub: userId,
          email,
          type: TokenType.REFRESH,
          sessionId: session.id,
          remember,
        },
        refreshExpiry,
      );

    return {
      accessToken,
      accessTokenExpiresAt,
      refreshToken,
      refreshTokenExpiresAt,
    };
  }

  // ============================================================================
  // PRIVATE — VERIFICATION CODE MANAGEMENT
  // ============================================================================

  /**
   * Upserts a verification code record for the given user and type.
   * Returns the plain OTP (to be emailed) and the argon2 hash (stored in DB).
   */
  private async createVerificationCode(
    userId: string,
    type: VerificationType,
    attempts: number = 1,
    expiryMinutes: number = 1440,
    urlToken?: string,
  ): Promise<{ otp: string; hashedOtp: string }> {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = await hash(otp);
    const expiresAt = new Date(Date.now() + expiryMinutes * 60_000);
    const validAttempts = Math.max(attempts, 1);

    await this.prisma.verificationCode.upsert({
      where: { userId_type: { userId, type } },
      create: {
        userId,
        type,
        code: hashedOtp,
        urlToken: urlToken ?? null,
        attempts: validAttempts,
        lastSentAt: new Date(),
        expiresAt,
      },
      update: {
        code: hashedOtp,
        urlToken: urlToken ?? null,
        attempts: validAttempts,
        lastSentAt: new Date(),
        expiresAt,
      },
    });

    return { otp, hashedOtp };
  }

  // ============================================================================
  // PRIVATE — UNIFIED MAIL DISPATCH
  // ============================================================================

  /**
   * Unified mail dispatcher for both email-verification and password-reset flows.
   * Builds the correct URL and calls the appropriate mail service method based on type.
   *
   * Replaces the two separate `dispatchEmailVerificationMail` and
   * `dispatchPasswordResetMail` methods which were structurally identical.
   */
  private async dispatchMail(
    type: 'EMAIL_VERIFICATION' | 'PASSWORD_RESET',
    email: string,
    name: string,
    otp: string,
    urlToken: string,
  ): Promise<void> {
    const base = this.config.get<string>('frontend.url');

    if (type === VerificationType.EMAIL_VERIFICATION) {
      const verifyUrl = `${base}/verify-email?token=${urlToken}&code=${otp}`;
      await this.mailService.sendVerificationEmail(email, otp, name, verifyUrl);
    } else {
      const resetUrl = `${base}/verify-reset?token=${urlToken}&code=${otp}`;
      await this.mailService.sendPasswordResetEmail(email, otp, name, resetUrl);
    }
  }

  // ============================================================================
  // PRIVATE — EXPONENTIAL BACKOFF CALCULATOR
  // ============================================================================

  /**
   * Calculates how many seconds must elapse before the next resend is allowed.
   *
   * Backoff schedule (30 s × 2^(attempt-1), max 2 h):
   *  Attempt 1 → 30 s  |  Attempt 2 → 1 min  |  Attempt 3 → 2 min …
   */
  private calcRetryDelay(lastSentAt: Date, attempts: number): DurationResult {
    const requiredMs = Math.min(
      30_000 * Math.pow(2, Math.max(attempts - 1, 0)),
      7_200_000, // 2 h cap
    );
    const elapsed = Date.now() - lastSentAt.getTime();
    const remainingMs = Math.max(requiredMs - elapsed, 0);
    const waitSeconds = Math.ceil(remainingMs / 1000);

    if (waitSeconds <= 0)
      return { waitSeconds: 0, breakdown: {}, waitFormatted: '' };

    const breakdown: DurationBreakdown = {};
    let rem = waitSeconds;

    breakdown.days = Math.floor(rem / 86400);
    rem %= 86400;
    breakdown.hours = Math.floor(rem / 3600);
    rem %= 3600;
    breakdown.minutes = Math.floor(rem / 60);
    rem %= 60;
    breakdown.seconds = rem;

    const parts: string[] = [];

    if (breakdown.days)
      parts.push(
        this.i18n.translate(
          breakdown.days === 1 ? 'common.duration.day' : 'common.duration.days',
          { args: { count: breakdown.days } },
        ),
      );
    if (breakdown.hours)
      parts.push(
        this.i18n.translate(
          breakdown.hours === 1
            ? 'common.duration.hour'
            : 'common.duration.hours',
          { args: { count: breakdown.hours } },
        ),
      );
    if (breakdown.minutes)
      parts.push(
        this.i18n.translate(
          breakdown.minutes === 1
            ? 'common.duration.minute'
            : 'common.duration.minutes',
          { args: { count: breakdown.minutes } },
        ),
      );
    if (breakdown.seconds)
      parts.push(
        this.i18n.translate(
          breakdown.seconds === 1
            ? 'common.duration.second'
            : 'common.duration.seconds',
          { args: { count: breakdown.seconds } },
        ),
      );

    return { waitSeconds, breakdown, waitFormatted: parts.join(' ').trim() };
  }

  // ============================================================================
  // PRIVATE — USERNAME HELPERS
  // ============================================================================

  /**
   * Derives a sanitized username from the local part of an email, then
   * appends an incrementing counter until a unique slot is found.
   * Example: "john.doe@x.com" → "john.doe" → "john.doe1" if taken → …
   */
  private async deriveUniqueUsernameFromEmail(email: string): Promise<string> {
    let base = email.split('@')[0];
    base = base.replace(/[^a-zA-Z0-9_.]/g, '_').replace(/^\.+|\.+$/g, '');
    if (base.length < 3) base = base + '_user';

    let candidate = base;
    let counter = 1;
    while (
      await this.prisma.user.findUnique({ where: { username: candidate } })
    ) {
      candidate = `${base}${counter++}`;
    }
    return candidate;
  }

  // ============================================================================
  // PRIVATE — FAKE USER STATE (CACHE)
  // ============================================================================

  /**
   * Reads or initialises the in-cache state for a fake (non-existent) user.
   */
  private async fetchOrInitFakeUserState(
    userId: string,
    type: VerificationType,
  ): Promise<{
    attempts: number;
    lastRequestAt: Date;
    dailyMaxAttempts: number;
  }> {
    const cacheKey = `fake-user:${userId}:${type}`;
    const cached = await this.cache.get<{
      attempts: number;
      lastRequestAt: number;
    }>(cacheKey);

    const dailyMaxAttempts =
      type === VerificationType.EMAIL_VERIFICATION ? 7 : 5;

    if (!cached) {
      const state = { attempts: 1, lastRequestAt: Date.now() };
      await this.cache.set(cacheKey, state, 86400);
      return {
        attempts: 1,
        lastRequestAt: new Date(state.lastRequestAt),
        dailyMaxAttempts,
      };
    }

    const lastReq = new Date(cached.lastRequestAt);
    const isSameDay = this.isSameCalendarDay(new Date(), lastReq);

    if (!isSameDay) {
      const state = { attempts: 1, lastRequestAt: Date.now() };
      await this.cache.set(cacheKey, state, 86400);
      return {
        attempts: 1,
        lastRequestAt: new Date(state.lastRequestAt),
        dailyMaxAttempts,
      };
    }

    const state = { attempts: cached.attempts + 1, lastRequestAt: Date.now() };
    await this.cache.set(cacheKey, state, 86400);
    return {
      attempts: state.attempts,
      lastRequestAt: new Date(state.lastRequestAt),
      dailyMaxAttempts,
    };
  }

  // ============================================================================
  // PRIVATE — TIMING SIMULATION
  // ============================================================================

  /**
   * Introduces a randomised delay that mimics real DB + argon2 processing time.
   * Used exclusively in fake-user paths to prevent timing-based user enumeration.
   */
  private async simulateDbDelay(): Promise<void> {
    const components = [
      Math.random() * 50 + 50,
      Math.random() * 50 + 30,
      Math.random() * 10 + 10,
      Math.random() * 5 + 5,
      Math.random() * 10 + 20,
      Math.random() * 50 + 40,
      Math.random() * 200 + 100,
    ];
    const total = components.reduce((a, b) => a + b, 0);
    const jitter = (Math.random() - 0.5) * 50;
    await new Promise((r) => setTimeout(r, total + jitter));
  }

  // ============================================================================
  // PRIVATE — CRYPTO HELPERS
  // ============================================================================

  /** Generates a 64-character hex secret for the password-reset rotation mechanism. */
  private generateResetSecret(): string {
    return randomBytes(32).toString('hex');
  }

  /** Generates a 16-character URL-safe base64 token for email magic links. */
  private generateUrlToken(): string {
    return randomBytes(12).toString('base64url');
  }
}
