/**
 *
 * Usage:
 *   @Auth(TokenType.EMAIL_VERIFICATION)
 *   @Post('email/resend-otp')
 *   resendEmailOtp(...) {}
 */

import {
  AuthUser,
  JwtPayload,
  TOKEN_PRIVILEGE,
  TokenType,
} from '@/common/types/jwt.type';
import { PrismaService } from '@/prisma/prisma.service';
import {
  applyDecorators,
  CanActivate,
  ExecutionContext,
  Injectable,
  SetMetadata,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { VerificationType } from 'generated/prisma/enums';
import { I18nService } from 'nestjs-i18n';
import { ExtractJwt } from 'passport-jwt';

// ─────────────────────────────────────────────────────────────────────────────
// Internal metadata key — not exported; only FlowGuard and @Auth() touch it.
// ─────────────────────────────────────────────────────────────────────────────

const FLOW_TOKEN_TYPE_KEY = 'flowTokenType';

// ─────────────────────────────────────────────────────────────────────────────
// Internal map — TokenType → VerificationType for DB secret validation.
// Only challenge-token types that carry a rotating flowSecret are listed.
// ─────────────────────────────────────────────────────────────────────────────

const TOKEN_TO_VERIFICATION_TYPE: Partial<Record<TokenType, VerificationType>> =
  {
    [TokenType.EMAIL_VERIFICATION]: VerificationType.EMAIL_VERIFICATION,
    [TokenType.PASSWORD_RESET_VERIFICATION]: VerificationType.PASSWORD_RESET,
    [TokenType.PASSWORD_RESET]: VerificationType.PASSWORD_RESET,
    [TokenType.TWO_FACTOR]: VerificationType.TWO_FACTOR_AUTH,
  };

/**
 *
 * Superiority rule:
 *   TOKEN_PRIVILEGE determines access level.  An ACCESS token (privilege 100)
 *   satisfies any lower-privilege gate — a fully-authenticated user can call
 *   any @Auth()-protected endpoint without holding a challenge token.
 *
 * Invalidation (shuffle-secret mechanism):
 *   Every challenge JWT embeds a `flowSecret` that mirrors the `flowSecret`
 *   column on the VerificationCode row for that user + type.
 *   The guard fetches that row on every request and compares.
 *   Deleting the row (task done) or rotating its secret (new OTP sent)
 *   instantly rejects every in-flight JWT for that flow —
 *   no blacklist table, no extra User column, no cron job required.
 */
@Injectable()
export class FlowGuard implements CanActivate {
  private readonly jwtExtractor = ExtractJwt.fromAuthHeaderAsBearerToken();

  constructor(
    private readonly reflector: Reflector,
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly i18n: I18nService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredType = this.reflector.getAllAndOverride<TokenType>(
      FLOW_TOKEN_TYPE_KEY,
      [context.getHandler(), context.getClass()],
    );

    // Guard applied without @Auth() metadata — treat as open (should not happen).
    if (!requiredType) return true;

    const request = context
      .switchToHttp()
      .getRequest<Request & { user: AuthUser }>();

    const rawToken = this.jwtExtractor(request);

    if (!rawToken) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.tokenRequired'),
      );
    }

    let payload: JwtPayload;

    try {
      payload = this.jwtService.verify<JwtPayload>(rawToken);
    } catch (err) {
      if (err instanceof Error && err.name === 'TokenExpiredError') {
        throw new UnauthorizedException(
          this.i18n.translate('auth.errors.tokenExpired'),
        );
      }
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.invalidToken'),
      );
    }

    const tokenPrivilege = TOKEN_PRIVILEGE[payload.type] ?? 0;
    const requiredPrivilege = TOKEN_PRIVILEGE[requiredType] ?? 0;

    if (tokenPrivilege < requiredPrivilege) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.invalidTokenType'),
      );
    }

    // Fake-user tokens (enumeration-protection) skip DB validation entirely.
    if (payload.isFakeUser) {
      request.user = this.buildUser(payload);
      return true;
    }

    // Validate the rotating flowSecret only for exact-type matches.
    // Superior tokens (e.g. ACCESS) skip this — session is their proof.
    const verificationType = TOKEN_TO_VERIFICATION_TYPE[payload.type];

    if (
      payload.type === requiredType &&
      verificationType &&
      payload.flowSecret
    ) {
      await this.validateFlowSecret(
        payload.sub,
        verificationType,
        payload.flowSecret,
      );
    }

    request.user = this.buildUser(payload);
    return true;
  }

  // ── private helpers ────────────────────────────────────────────────────────

  private buildUser(payload: JwtPayload): AuthUser {
    return {
      id: payload.sub,
      email: payload.email,
      sessionId: payload.sessionId,
      remember: payload.remember,
      flowSecret: payload.flowSecret,
      isFakeUser: payload.isFakeUser ?? false,
    };
  }

  /**
   * Core of the shuffle-secret invalidation:
   *   • Row deleted          → record null      → rejected
   *   • Secret rotated       → value mismatch   → rejected
   *   • User deactivated     → isActive false   → rejected
   */
  private async validateFlowSecret(
    userId: string,
    verificationType: VerificationType,
    flowSecret: string,
  ): Promise<void> {
    const record = await this.prisma.verificationCode.findUnique({
      where: { userId_type: { userId, type: verificationType } },
      select: {
        flowSecret: true,
        user: { select: { isActive: true } },
      },
    });

    if (!record || record.flowSecret !== flowSecret || !record.user?.isActive) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.errors.tokenInvalidated'),
      );
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// @Auth() — the only thing controller files should import from here.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @Auth(TokenType.X)
 *
 * Composes SetMetadata + UseGuards(FlowGuard) into a single decorator.
 *
 * Examples:
 *   @Auth(TokenType.EMAIL_VERIFICATION)   // email verify / resend OTP
 *   @Auth(TokenType.TWO_FACTOR)           // 2FA verify
 *   @Auth(TokenType.PASSWORD_RESET)       // set new password
 *
 * An ACCESS token always satisfies any @Auth() gate (superiority rule),
 * so an authenticated user never needs a challenge token for these endpoints.
 */
export const Auth = (tokenType: TokenType): MethodDecorator & ClassDecorator =>
  applyDecorators(
    SetMetadata(FLOW_TOKEN_TYPE_KEY, tokenType),
    UseGuards(FlowGuard),
  );
