/**
 * AppConfig
 *
 * Single source of truth for every configuration key used in the application.
 * Each field maps 1-to-1 to a key returned by configuration.ts and consumed
 * via ConfigService.get<T>('section.key').
 *
 * Keep in sync with:
 *  - src/config/configuration.ts   (the factory)
 *  - .env.example                  (the env reference)
 */

export type AppConfig = {
  // ─── Application ───────────────────────────────────────────────────────────
  app: {
    /** Human-readable application name. Used in emails, logs, TOTP issuer. */
    name: string;
    /** HTTP port the server listens on. */
    port: number;
    /** Runtime environment: 'development' | 'staging' | 'production' */
    env: string;
  };

  // ─── Internationalisation ──────────────────────────────────────────────────
  i18n: {
    /** BCP-47 language tag used when no match is found, e.g. 'en'. */
    defaultLanguage: string;
    /** Comma-separated list of supported language tags, e.g. ['en', 'es']. */
    availableLanguages: string[];
  };

  // ─── Database ──────────────────────────────────────────────────────────────
  database: {
    /** Full PostgreSQL connection string. */
    url: string;
  };

  // ─── JWT ───────────────────────────────────────────────────────────────────
  jwt: {
    /** Signing secret shared by all token types. */
    secret: string;

    /** Access token lifetime for regular (non-remember-me) sessions, e.g. '15m'. */
    expiresIn: string;

    /**
     * Access token lifetime when the user checked "remember me", e.g. '90d'.
     * Falls back to `expiresIn` if omitted.
     */
    rememberExpiresIn: string;

    /** Refresh token lifetime for regular sessions, e.g. '7d'. */
    refreshExpiresIn: string;

    /**
     * Refresh token lifetime for remember-me sessions, e.g. '60d'.
     * Falls back to `refreshExpiresIn` if omitted.
     */
    refreshRememberExpiresIn: string;

    /**
     * Lifetime of short-lived challenge tokens:
     *  - EMAIL_VERIFICATION
     *  - TWO_FACTOR
     *  - PASSWORD_RESET
     *  - PASSWORD_RESET_VERIFICATION
     *
     * e.g. '10m'
     */
    twoFactorExpiresIn: string;
  };

  // ─── CORS ──────────────────────────────────────────────────────────────────
  cors: {
    /** Allowed origin(s) for cross-origin requests, e.g. 'http://localhost:3000'. */
    origin: string;
  };

  // ─── Mail ──────────────────────────────────────────────────────────────────
  mail: {
    /** SMTP host, e.g. 'smtp.gmail.com'. */
    host: string;
    /** SMTP port — 465 (SSL) or 587 (STARTTLS). */
    port: number;
    /** SMTP authentication username / email. */
    user: string;
    /** SMTP authentication password or app-password. */
    password: string;
    /**
     * RFC-5321 From address shown to recipients.
     * e.g. '"My App" <no-reply@myapp.com>'
     */
    from: string;
  };

  // ─── Frontend ──────────────────────────────────────────────────────────────
  frontend: {
    /**
     * Base URL of the frontend application.
     * Used to build magic-link URLs sent in emails.
     * e.g. 'https://myapp.com'
     */
    url: string;
  };

  // ─── OTP / Verification expiry ─────────────────────────────────────────────
  expirity: {
    email: {
      /** Minutes before an email-verification OTP expires. Default: 30. */
      verification: number;
      /** Minutes before a password-reset OTP expires. Default: 30. */
      forget: number;
    };
  };

  // ─── Cache ─────────────────────────────────────────────────────────────────
  cache: {
    /** Default TTL in seconds for in-memory cache entries. Default: 300. */
    ttl: number;
    /** Maximum number of items held in the in-memory LRU cache. Default: 500. */
    max: number;
    redis: {
      /**
       * Set to true to use Redis as the primary cache.
       * When false (or Redis is unreachable) the app falls back to in-memory cache.
       */
      enabled: boolean;
      /**
       * Full Redis connection URL.
       * e.g. 'redis://localhost:6379' or 'rediss://user:pass@host:6380'
       * Null disables Redis even if `enabled` is true.
       */
      url: string | null;
    };
  };

  // ─── Verification rate-limiting ────────────────────────────────────────────
  verification: {
    /** Maximum total resend+verify attempts per user per day. Default: 7. */
    dailyMaxAttempts: number;
    /** Maximum OTP resend attempts per user per day. Default: 7. */
    dailyMaxResendAttempts: number;
    /** Maximum OTP verify attempts per user per day. Default: 10. */
    dailyMaxVerifyAttempts: number;
  };

  // ─── Registration rate-limiting ────────────────────────────────────────────
  registration: {
    /** Maximum new signups allowed per IP address per day. Default: 3. */
    maxDailySignups: number;
  };

  // ─── Two-Factor Authentication ─────────────────────────────────────────────
  twoFactor: {
    /** Master switch — set to false to disable 2FA across the entire app. */
    enabled: boolean;
    /**
     * TOTP application secret / issuer label shown in authenticator apps.
     * In production, supply a strong random value via env.
     */
    secret: string;
    /** How many backup codes are generated per user. Default: 10. */
    backupCodeCount: number;
    /** Milliseconds a user is locked out after exceeding max 2FA attempts. Default: 900000 (15 min). */
    lockupDuration: number;
  };
};
