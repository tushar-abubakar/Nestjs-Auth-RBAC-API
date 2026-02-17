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

@Injectable()
export class TwoFactorGuard implements CanActivate {
  private readonly jwtExtractor = ExtractJwt.fromAuthHeaderAsBearerToken();

  constructor(
    private jwtService: JwtService,
    private readonly i18n: I18nService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context
      .switchToHttp()
      .getRequest<Request & { user: AuthUser }>();
    const token = this.jwtExtractor(request);

    if (!token) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.two_factor_token_required'),
      );
    }

    try {
      const payload = this.jwtService.verify<JwtPayload>(token);

      if (payload.type !== TokenType.TWO_FACTOR) {
        throw new UnauthorizedException(
          this.i18n.translate('auth.invalid_token_type'),
        );
      }

      request.user = {
        id: payload.sub,
        email: payload.email,
        remember: payload.remember ?? false,
      };

      return true;
    } catch {
      throw new UnauthorizedException(
        this.i18n.translate('auth.invalid_or_expired_token'),
      );
    }
  }
}
