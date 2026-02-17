import { CurrentUser } from '@/common/decorators/current-user.decorator';
import { IpAddress } from '@/common/decorators/ip-address.decorator';
import { Public } from '@/common/decorators/public.decorator';
import { UserAgent } from '@/common/decorators/user-agent.decorator';
import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
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
import { EmailVerificationGuard } from './guards/email-verification.guard';
import { PasswordResetVerificationGuard } from './guards/password-reset-verification.guard';
import { PasswordResetGuard } from './guards/password-reset.guard';
import { TwoFactorGuard } from './guards/two-factor.guard';
import {
  AuthResponse,
  EmailResendResponse,
  PasswordResetOtpResponse,
  VerifyResetResponse,
} from './types/auth-user.type';

/**
 * Handles all authentication flows:
 *
 *  Registration & email verification
 *  ├─ POST   /auth/register
 *  ├─ POST   /auth/email/verify-otp    ← manual OTP entry (JWT-gated)
 *  ├─ GET    /auth/email/verify-link   ← magic-link click (no JWT)
 *  └─ POST   /auth/email/resend-otp   ← resend code (JWT-gated)
 *
 *  Login & 2FA
 *  ├─ POST   /auth/login
 *  └─ POST   /auth/two-factor/verify   ← TOTP verify (JWT-gated)
 *
 *  Session management
 *  └─ POST   /auth/token/refresh
 *
 *  Password reset
 *  ├─ POST   /auth/password/forgot          ← step 1 – initiate
 *  ├─ POST   /auth/password/resend-otp      ← step 1 – resend (JWT-gated)
 *  ├─ POST   /auth/password/verify-otp      ← step 2a – OTP entry (JWT-gated)
 *  ├─ GET    /auth/password/verify-link     ← step 2b – link click (no JWT)
 *  └─ POST   /auth/password/reset           ← step 3 – set new password (JWT-gated)
 */
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // ──────────────────────────────────────────────────────────────────────────
  // REGISTRATION
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * POST /auth/register
   *
   * Creates a new user account.  When email verification is required (the
   * default) the response carries an EMAIL_VERIFICATION challenge containing a
   * short-lived `verificationToken` to be used with /auth/email/verify-otp or
   * /auth/email/resend-otp.  If verification is disabled the response is
   * AUTHENTICATED with full session tokens.
   */
  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  register(
    @Body() dto: RegisterDto,
    @UserAgent() userAgent: string,
    @IpAddress() ipAddress: string,
  ): Promise<AuthResponse> {
    return this.authService.register(dto, userAgent, ipAddress);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // EMAIL VERIFICATION
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * POST /auth/email/verify-otp
   *
   * Verifies the user's email address using the 6-digit OTP they received.
   * Requires a valid EMAIL_VERIFICATION bearer token (issued at registration
   * or by /auth/email/resend-otp).
   *
   * Rate-limited: 5 cache attempts / 15 min + daily DB limit.
   *
   * On success:
   *  • 2FA enabled  → TWO_FACTOR_REQUIRED challenge
   *  • otherwise    → AUTHENTICATED with session tokens
   */
  @Public()
  @Post('email/verify-otp')
  @UseGuards(EmailVerificationGuard)
  @HttpCode(HttpStatus.OK)
  verifyEmailOtp(
    @Body() dto: VerifyEmailDto,
    @CurrentUser('id') userId: string,
    @UserAgent() userAgent: string,
    @IpAddress() ipAddress: string,
  ): Promise<AuthResponse> {
    return this.authService.verifyEmailOtpAndLogin(
      dto,
      userId,
      userAgent,
      ipAddress,
    );
  }

  /**
   * GET /auth/email/verify-link?token=<urlToken>&code=<otp>
   *
   * Verifies the user's email via the magic link from their email.
   * No JWT guard — the `urlToken` query param is the bearer credential.
   *
   * Rate-limited: 5 attempts / 15 min per token + 10 / 15 min per IP.
   *
   * On success mirrors verify-otp: 2FA challenge or AUTHENTICATED tokens.
   */
  @Public()
  @Get('email/verify-link')
  @HttpCode(HttpStatus.OK)
  verifyEmailLink(
    @Query('token') urlToken: string,
    @Query('code') code: string,
    @UserAgent() userAgent: string,
    @IpAddress() ipAddress: string,
  ): Promise<AuthResponse> {
    return this.authService.verifyEmailLinkAndLogin(
      urlToken,
      code,
      userAgent,
      ipAddress,
    );
  }

  /**
   * POST /auth/email/resend-otp
   *
   * Resends the email-verification OTP.  Requires the same EMAIL_VERIFICATION
   * bearer token as verify-otp.  Subject to IP, user-level, and cache rate limits
   * plus exponential back-off between sends.
   */
  @Public()
  @Post('email/resend-otp')
  @UseGuards(EmailVerificationGuard)
  @HttpCode(HttpStatus.OK)
  resendEmailVerificationOtp(
    @CurrentUser('id') userId: string,
    @IpAddress() ipAddress: string,
  ): Promise<EmailResendResponse> {
    return this.authService.resendEmailVerificationOtp(userId, ipAddress);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // LOGIN & TWO-FACTOR
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * POST /auth/login
   *
   * Authenticates with email/username + password.
   * Rate-limited: 5 failed attempts / 15 min per identifier.
   *
   * Possible outcomes:
   *  • AUTHENTICATED          → full session tokens
   *  • TWO_FACTOR_REQUIRED    → short-lived twoFactorToken challenge
   *  • ForbiddenException     → account inactive or email unverified
   */
  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(
    @Body() dto: LoginDto,
    @UserAgent() userAgent: string,
    @IpAddress() ipAddress: string,
  ): Promise<AuthResponse> {
    return this.authService.login(dto, userAgent, ipAddress);
  }

  /**
   * POST /auth/two-factor/verify
   *
   * Completes the 2FA step.  Requires a valid TWO_FACTOR bearer token issued
   * by /auth/login or /auth/email/verify-otp.  Verifies the TOTP code and,
   * on success, returns AUTHENTICATED session tokens.
   */
  @Public()
  @Post('two-factor/verify')
  @UseGuards(TwoFactorGuard)
  @HttpCode(HttpStatus.OK)
  completeTwoFactorLogin(
    @Body() dto: Verify2FADto,
    @CurrentUser('id') userId: string,
    @IpAddress() ipAddress: string,
    @UserAgent() userAgent: string,
    @CurrentUser('remember') remember: boolean,
  ): Promise<AuthResponse> {
    return this.authService.completeTwoFactorLogin(
      dto,
      userId,
      ipAddress,
      userAgent,
      remember,
    );
  }

  // ──────────────────────────────────────────────────────────────────────────
  // SESSION MANAGEMENT
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * POST /auth/token/refresh
   *
   * Rotates the refresh token: the supplied token is invalidated and a fresh
   * access + refresh token pair is issued.  The `remember` preference from the
   * original session is preserved so token lifetimes stay consistent.
   */
  @Public()
  @Post('token/refresh')
  @HttpCode(HttpStatus.OK)
  rotateRefreshToken(
    @Body() dto: RefreshTokenDto,
    @UserAgent() userAgent: string,
    @IpAddress() ipAddress: string,
  ): Promise<AuthResponse> {
    return this.authService.rotateRefreshToken(dto, userAgent, ipAddress);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // PASSWORD RESET — STEP 1: INITIATE
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * POST /auth/password/forgot
   *
   * Initiates the password-reset flow.  Sends a 6-digit OTP + magic link to
   * the address associated with the given email/username.
   *
   * The response is structurally identical whether or not the identifier
   * exists, to prevent user enumeration.  A `verificationToken` is always
   * returned; for non-existent users it is a fake token with `isFakeUser: true`
   * embedded so subsequent resend/verify calls can mirror real behaviour.
   *
   * Rate-limited: 10 requests / hr per IP.
   */
  @Public()
  @Post('password/forgot')
  @HttpCode(HttpStatus.OK)
  initiatePasswordReset(
    @Body() dto: ForgotPasswordDto,
    @IpAddress() ipAddress: string,
  ): Promise<PasswordResetOtpResponse> {
    return this.authService.initiatePasswordReset(dto, ipAddress);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // PASSWORD RESET — STEP 1 (RESEND)
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * POST /auth/password/resend-otp
   *
   * Resends the password-reset OTP.  Requires the PASSWORD_RESET_VERIFICATION
   * token returned by /auth/password/forgot.
   *
   * Applies the same exponential back-off and daily limits as the initial
   * request.  Fake-user flows are silently simulated with realistic delays.
   */
  @Public()
  @Post('password/resend-otp')
  @UseGuards(PasswordResetVerificationGuard)
  @HttpCode(HttpStatus.OK)
  resendPasswordResetOtp(
    @CurrentUser('id') userId: string,
    @CurrentUser('isFakeUser') isFakeUser: boolean,
    @IpAddress() ipAddress: string,
  ): Promise<PasswordResetOtpResponse> {
    return this.authService.resendPasswordResetOtp(
      userId,
      isFakeUser,
      ipAddress,
    );
  }

  // ──────────────────────────────────────────────────────────────────────────
  // PASSWORD RESET — STEP 2A: VERIFY OTP
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * POST /auth/password/verify-otp
   *
   * Verifies the 6-digit password-reset OTP (manual entry path).
   * Requires the PASSWORD_RESET_VERIFICATION bearer token.
   *
   * On success returns a short-lived `resetToken` (10 min) to be used with
   * /auth/password/reset.  The OTP record is deleted and the reset secret is
   * rotated so this token cannot be reused.
   */
  @Public()
  @Post('password/verify-otp')
  @UseGuards(PasswordResetVerificationGuard)
  @HttpCode(HttpStatus.OK)
  verifyPasswordResetOtp(
    @Body() dto: VerifyResetCodeDto,
    @CurrentUser('id') userId: string,
    @CurrentUser('secret') secret: string,
    @CurrentUser('isFakeUser') isFakeUser: boolean,
  ): Promise<VerifyResetResponse> {
    return this.authService.verifyPasswordResetOtp(
      dto,
      userId,
      secret,
      isFakeUser,
    );
  }

  // ──────────────────────────────────────────────────────────────────────────
  // PASSWORD RESET — STEP 2B: VERIFY LINK
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * GET /auth/password/verify-link?token=<urlToken>&code=<otp>
   *
   * Verifies the password-reset magic link the user clicked in their email.
   * No JWT guard — the `urlToken` query param is the bearer credential.
   *
   * On success returns the same `resetToken` as the OTP path.
   */
  @Public()
  @Get('password/verify-link')
  @HttpCode(HttpStatus.OK)
  verifyPasswordResetLink(
    @Query('token') urlToken: string,
    @Query('code') code: string,
  ): Promise<VerifyResetResponse> {
    return this.authService.verifyPasswordResetLink(urlToken, code);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // PASSWORD RESET — STEP 3: SET NEW PASSWORD
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * POST /auth/password/reset
   *
   * Sets a new password.  Requires the PASSWORD_RESET bearer token issued by
   * /auth/password/verify-otp or /auth/password/verify-link.
   *
   * After the password is updated:
   *  • 2FA enabled  → TWO_FACTOR_REQUIRED challenge (user must re-verify TOTP)
   *  • otherwise    → AUTHENTICATED with fresh session tokens
   *
   * Optionally deletes all existing sessions (default: true) to log out other
   * devices after a password change.
   */
  @Public()
  @Post('password/reset')
  @UseGuards(PasswordResetGuard)
  @HttpCode(HttpStatus.OK)
  resetPassword(
    @Body() dto: SetNewPasswordDto,
    @CurrentUser('id') userId: string,
    @CurrentUser('secret') secret: string,
    @UserAgent() userAgent: string,
    @IpAddress() ipAddress: string,
  ): Promise<AuthResponse> {
    return this.authService.resetPassword(
      dto,
      userId,
      secret,
      userAgent,
      ipAddress,
    );
  }
}
