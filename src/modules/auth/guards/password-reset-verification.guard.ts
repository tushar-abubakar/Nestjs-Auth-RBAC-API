import { AuthUser, JwtPayload, TokenType } from '@/common/types/jwt.type';
import { PrismaService } from '@/prisma/prisma.service';
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { I18nService } from 'nestjs-i18n';
import { ExtractJwt } from 'passport-jwt';

/**
 * Guards endpoints in the password-reset OTP verification step
 * (POST /auth/password/verify-otp, POST /auth/password/resend-otp).
 *
 * Responsibilities:
 *  1. Verify JWT signature and expiry.
 *  2. Assert token type is PASSWORD_RESET_VERIFICATION.
 *  3. For real users: fetch the user row and confirm the rotating
 *     `passwordResetSecret` embedded in the token still matches the DB.
 *     This invalidates every in-flight reset token the moment a new one
 *     is issued (or the password is changed).
 *  4. For fake users (enumeration-protection tokens): skip DB look-up
 *     and surface the `isFakeUser` flag so the service can mirror the
 *     same response shape without touching real data.
 *
 * Note: `codeHash` is intentionally NOT forwarded — OTP correctness is
 * verified in the service layer against the DB record only.
 */
@Injectable()
export class PasswordResetVerificationGuard implements CanActivate {
  private readonly jwtExtractor = ExtractJwt.fromAuthHeaderAsBearerToken();

  constructor(
    private readonly i18n: I18nService,
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<Request & { user: AuthUser }>();

    const token = this.jwtExtractor(request);

    if (!token) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.verification_token_required'),
      );
    }

    try {
      const payload = this.jwtService.verify<JwtPayload>(token);

      if (payload.type !== TokenType.PASSWORD_RESET_VERIFICATION) {
        throw new UnauthorizedException(
          this.i18n.translate('auth.invalid_token_type'),
        );
      }

      // Fake-user tokens skip DB validation to avoid data leakage
      if (!payload.isFakeUser) {
        const user = await this.prisma.user.findUnique({
          where: { id: payload.sub },
          select: { passwordResetSecret: true, isActive: true },
        });

        if (!user?.isActive) {
          throw new UnauthorizedException(
            this.i18n.translate('auth.account_inactive'),
          );
        }

        if (
          !user.passwordResetSecret ||
          user.passwordResetSecret !== payload.secret
        ) {
          throw new UnauthorizedException(
            this.i18n.translate('auth.reset_token_invalidated'),
          );
        }
      }

      request.user = {
        id: payload.sub,
        email: payload.email,
        secret: payload.secret,
        isFakeUser: payload.isFakeUser ?? false,
      };

      return true;
    } catch (error) {
      if (error instanceof Error && error.name === 'TokenExpiredError') {
        throw new UnauthorizedException(
          this.i18n.translate('auth.verification_token_expired'),
        );
      }
      throw new UnauthorizedException(
        this.i18n.translate('auth.invalid_verification_token'),
      );
    }
  }
}
