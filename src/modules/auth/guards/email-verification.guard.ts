import { AuthUser, JwtPayload, TokenType } from '@/common/types/jwt.type';
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
 * Guards endpoints that require an EMAIL_VERIFICATION token
 * (e.g. POST /auth/email/verify-otp, POST /auth/email/resend-otp).
 *
 * Extracts the bearer token, verifies its signature and expiry,
 * asserts the token type is EMAIL_VERIFICATION, then populates
 * `request.user` with the minimal fields needed by downstream handlers.
 *
 * Note: `codeHash` is intentionally NOT forwarded.  The OTP code is
 * validated exclusively against the database record, so carrying the
 * hash through the request object would be redundant and misleading.
 */
@Injectable()
export class EmailVerificationGuard implements CanActivate {
  private readonly jwtExtractor = ExtractJwt.fromAuthHeaderAsBearerToken();

  constructor(
    private readonly i18n: I18nService,
    private readonly jwtService: JwtService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context
      .switchToHttp()
      .getRequest<Request & { user: AuthUser }>();

    const token = this.jwtExtractor(request);

    if (!token) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.email_verification_token_required'),
      );
    }

    try {
      const payload = this.jwtService.verify<JwtPayload>(token);

      if (payload.type !== TokenType.EMAIL_VERIFICATION) {
        throw new UnauthorizedException(
          this.i18n.translate('auth.invalid_token_type'),
        );
      }

      request.user = {
        id: payload.sub,
        email: payload.email,
      };

      return true;
    } catch (error) {
      if (error instanceof Error && error.name === 'TokenExpiredError') {
        throw new UnauthorizedException(
          this.i18n.translate('auth.expired_email_verify_token'),
        );
      }
      throw new UnauthorizedException(
        this.i18n.translate('auth.invalid_email_verify_token'),
      );
    }
  }
}
