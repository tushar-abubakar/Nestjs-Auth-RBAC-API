import { AppConfig } from '@/common/types/config.type';

/**
 * Configuration factory loaded by ConfigModule.forRoot({ load: [configuration] }).
 *
 */
export default (): AppConfig => ({
  // ─── Application ───────────────────────────────────────────────────────────
  app: {
    name: process.env.APP_NAME ?? 'NestAuthShield',
    port: parseInt(process.env.PORT ?? '3000', 10),
    env: process.env.NODE_ENV ?? 'development',
  },

  // ─── Internationalisation ──────────────────────────────────────────────────
  i18n: {
    defaultLanguage: process.env.FALLBACK_LANGUAGE ?? 'en',
    availableLanguages: process.env.AVAILABLE_LANGUAGES?.split(',') ?? [
      'en',
      'es',
    ],
  },

  // ─── Database ──────────────────────────────────────────────────────────────
  database: {
    url: process.env.DATABASE_URL ?? '',
  },

  // ─── JWT ───────────────────────────────────────────────────────────────────
  jwt: {
    secret: process.env.JWT_SECRET ?? 'my-jwt-secret',

    // Regular session access token (short-lived)
    expiresIn: process.env.JWT_EXPIRES_IN ?? '15m',

    // Remember-me access token (long-lived)
    rememberExpiresIn: process.env.JWT_REMEMBER_EXPIRES_IN ?? '90d',

    // Regular session refresh token
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? '7d',

    // Remember-me refresh token (extra long)
    refreshRememberExpiresIn:
      process.env.JWT_REFRESH_REMEMBER_EXPIRES_IN ?? '60d',

    // Short-lived challenge tokens (2FA, email verification, password reset)
    twoFactorExpiresIn: process.env.JWT_2FA_EXPIRES_IN ?? '10m',
  },

  // ─── CORS ──────────────────────────────────────────────────────────────────
  cors: {
    origin: process.env.CORS_ORIGIN ?? 'http://localhost:8000',
  },

  // ─── Mail ──────────────────────────────────────────────────────────────────
  mail: {
    host: process.env.MAIL_HOST ?? '',
    port: parseInt(process.env.MAIL_PORT ?? '587', 10),
    user: process.env.MAIL_USER ?? '',
    password: process.env.MAIL_PASSWORD ?? '',
    from:
      process.env.MAIL_FROM ??
      `"${process.env.APP_NAME ?? 'NestAuthShield'}" <no-reply@example.com>`,
  },

  // ─── Frontend ──────────────────────────────────────────────────────────────
  frontend: {
    url: process.env.FRONTEND_URL ?? 'http://localhost:8000',
  },

  // ─── OTP / Verification expiry ─────────────────────────────────────────────
  expirity: {
    email: {
      verification: parseInt(
        process.env.EMAIL_VERIFICATION_EXPIRATION ?? '30',
        10,
      ),
      forget: parseInt(process.env.FORGET_PASSWORD_EXPIRATION ?? '30', 10),
    },
  },

  // ─── Cache ─────────────────────────────────────────────────────────────────
  cache: {
    ttl: parseInt(process.env.CACHE_TTL ?? '300', 10),
    max: parseInt(process.env.CACHE_MAX_ITEMS ?? '500', 10),
    redis: {
      enabled: process.env.REDIS_ENABLED === 'true',
      url: process.env.REDIS_URL ?? null,
    },
  },

  // ─── Verification rate-limiting ────────────────────────────────────────────
  verification: {
    dailyMaxAttempts: parseInt(process.env.MAX_RESEND_ATTEMPTS ?? '7', 10),
    dailyMaxResendAttempts: parseInt(
      process.env.MAX_DAILY_RESEND_ATTEMPTS ?? '7',
      10,
    ),
    dailyMaxVerifyAttempts: parseInt(
      process.env.MAX_DAILY_VERIFY_ATTEMPTS ?? '10',
      10,
    ),
  },

  // ─── Registration rate-limiting ────────────────────────────────────────────
  registration: {
    maxDailySignups: parseInt(process.env.MAX_DAILY_SIGNUPS ?? '3', 10),
  },

  // ─── Two-Factor Authentication ─────────────────────────────────────────────
  twoFactor: {
    enabled: process.env.TWO_FACTOR_ENABLED !== 'false',
    secret: process.env.TWO_FACTOR_SECRET ?? 'totp-secret',
    backupCodeCount: parseInt(process.env.TWO_FACTOR_BACKUP_CODES ?? '10', 10),
    lockupDuration: parseInt(
      process.env.TWO_FACTOR_LOCKOUT_DURATION ?? String(15 * 60 * 1000),
      10,
    ),
  },
});
