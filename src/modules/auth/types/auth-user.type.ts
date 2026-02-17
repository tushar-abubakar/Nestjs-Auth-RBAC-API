import { HttpStatus } from '@nestjs/common/enums';

/* ================= AUTH STATUS ================= */

export enum AuthStatus {
  AUTHENTICATED = 'authenticated',
  EMAIL_VERIFICATION_REQUIRED = 'email_verification_required',
  TWO_FACTOR_REQUIRED = 'two_factor_required',
}

/* ================= REUSABLE TYPES ================= */

type AuthTokens = {
  accessToken: string;
  accessTokenExpiresAt: string;
  refreshToken: string;
  refreshTokenExpiresAt: string;
};

type EmailVerificationData = {
  verificationToken: string;
  verificationTokenExpiresAt: string;
  retryAfterSeconds: number;
};

type TwoFactorData = {
  twoFactorToken: string;
  twoFactorTokenExpiresAt: string;
};

/* ================= GENERIC BASE ================= */

/**
 * Generic builder for all auth responses.
 *  S = status discriminator
 *  D = additional payload
 */
type AuthResponseBase<
  S extends AuthStatus,
  D extends object = Record<string, never>,
> = {
  status: S;
  userId: string;
  message?: string;
} & D;

/* ================= CONCRETE AUTH RESPONSES ================= */

export type AuthenticatedResponse = AuthResponseBase<
  AuthStatus.AUTHENTICATED,
  { tokens: AuthTokens }
>;

export type EmailVerificationRequiredResponse = AuthResponseBase<
  AuthStatus.EMAIL_VERIFICATION_REQUIRED,
  { challenge: EmailVerificationData }
>;

export type TwoFactorRequiredResponse = AuthResponseBase<
  AuthStatus.TWO_FACTOR_REQUIRED,
  { challenge: TwoFactorData }
>;

/** Union returned by register, login, verify-email, verify-2fa, and refresh. */
export type AuthResponse =
  | AuthenticatedResponse
  | EmailVerificationRequiredResponse
  | TwoFactorRequiredResponse;

/* ================= PASSWORD RESET RESPONSES ================= */

/**
 * Returned by POST /auth/password/forgot **and** POST /auth/password/resend-otp.
 *
 * Both endpoints rotate the `passwordResetSecret` and issue a fresh signed
 * `verificationToken`, so they share an identical response shape.
 * The caller always receives a new token they must use for subsequent steps —
 * any previously held token is invalidated by the secret rotation.
 */
export interface PasswordResetOtpResponse {
  verificationToken: string;
  verificationTokenExpiresAt: string;
  retryAfterSeconds: number;
  attemptsRemaining: number;
  message?: string;
}

/** Returned by GET/POST /auth/password/verify-otp and /auth/password/verify-link. */
export interface VerifyResetResponse {
  resetToken: string;
  resetTokenExpiresAt: string;
  message?: string;
}

/* ================= EMAIL VERIFICATION RESEND RESPONSE ================= */

/**
 * Returned by POST /auth/email/resend-otp.
 * Does NOT rotate or return a token — the original EMAIL_VERIFICATION JWT
 * issued at registration is still valid and must be reused.
 */
export interface EmailResendResponse {
  retryAfterSeconds: number;
  attemptsRemaining: number;
  statusCode?: HttpStatus;
  message?: string;
}
