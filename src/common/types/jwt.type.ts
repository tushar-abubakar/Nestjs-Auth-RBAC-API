/**
 * JWT Token Types
 * Each type has specific purpose and expiration
 */
export enum TokenType {
  ACCESS = 'access',
  REFRESH = 'refresh',
  EMAIL_VERIFICATION = 'email_verification',
  TWO_FACTOR = 'two_factor',
  PASSWORD_RESET = 'password_reset',
  PASSWORD_RESET_VERIFICATION = 'password_reset_verification',
}

/**
 * JWT Payload Interface
 * Contains all possible fields used across different token types
 */
export interface JwtPayload {
  sub: string;
  type: TokenType;
  email: string;
  exp?: number;
  iat?: number;

  // For password reset tokens
  secret?: string;
  isFakeUser?: boolean;

  // For auth tokens
  sessionId?: string;
  remember?: boolean;
}

/**
 * The shape attached to `request.user` by every auth guard.
 * Guards extract only the fields relevant to their token type.
 */
export interface AuthUser {
  id: string;
  email: string;
  sessionId?: string;
  name?: string;
  username?: string;
  roleId?: string;
  roleCode?: string;
  permissions?: string[];
  remember?: boolean;
  secret?: string;
  isFakeUser?: boolean;
}
