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
 * Privilege level for each token type (higher = more access).
 * Used by FlowGuard to allow superior tokens to bypass lower-privilege gates.
 */
export const TOKEN_PRIVILEGE: Record<TokenType, number> = {
  [TokenType.ACCESS]: 100,
  [TokenType.REFRESH]: 50,
  [TokenType.TWO_FACTOR]: 30,
  [TokenType.PASSWORD_RESET]: 20,
  [TokenType.PASSWORD_RESET_VERIFICATION]: 10,
  [TokenType.EMAIL_VERIFICATION]: 5,
};

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
  flowSecret?: string;
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
  username?: string;
  firstName?: string;
  lastName?: string;
  sessionId?: string;
  roleId?: string;
  roleCode?: string;
  permissions?: string[];
  remember?: boolean;
  flowSecret?: string;
  isFakeUser?: boolean;
}
