export const AUTH_CONSTANTS = {
  TEMP_TOKEN_EXPIRY: '15m',
  TWO_FACTOR_TOKEN_EXPIRY: '10m',
  EMAIL_VERIFICATION_TOKEN_EXPIRY: '30m',
  PASSWORD_RESET_TOKEN_EXPIRY: '30m',

  MAX_VERIFICATION_ATTEMPTS: 5,
  MAX_LOGIN_ATTEMPTS: 5,
  LOGIN_ATTEMPT_WINDOW: 15 * 60 * 1000, // 15 minutes

  REMEMBER_ME_DURATION: '90d',

  OTP_LENGTH: 6,
  OTP_VALIDITY_MINUTES: 10,

  STEP_UP_DURATION: '15m',
  BACKUP_CODES_COUNT: 10,
  MAX_2FA_ATTEMPTS: 5,
  TWO_FACTOR_LOCKOUT_DURATION: 15 * 60 * 1000,
};

export const CACHE_KEYS = {
  USER_PERMISSIONS: (userId: string): string => `permissions:user:${userId}`,
  LOGIN_ATTEMPTS: (identifier: string): string =>
    `login:attempts:${identifier}`,
  VERIFICATION_ATTEMPTS: (userId: string): string =>
    `verification:attempts:${userId}`,
  DAILY_SIGNUPS: (ip: string): string => `signups:daily:${ip}`,
  TWO_FACTOR_ATTEMPTS: (userId: string): string => `2fa:attempts:${userId}`,
  STEP_UP_VERIFIED: (userId: string, sessionId: string): string =>
    `stepup:${userId}:${sessionId}`,
};
