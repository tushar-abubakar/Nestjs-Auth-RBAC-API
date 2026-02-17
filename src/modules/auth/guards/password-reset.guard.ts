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

@Injectable()
export class PasswordResetGuard implements CanActivate {
  private readonly jwtExtractor = ExtractJwt.fromAuthHeaderAsBearerToken();

  constructor(
    private readonly i18n: I18nService,
    private jtwService: JwtService,
    private prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<
      Request & {
        user: AuthUser & {
          secret?: string;
        };
      }
    >();
    const token = this.jwtExtractor(request);

    if (!token) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.email_verification_token_required'),
      );
    }

    try {
      const payload = this.jtwService.verify<JwtPayload>(token);

      if (payload.type !== TokenType.PASSWORD_RESET) {
        throw new UnauthorizedException(
          this.i18n.translate('auth.invalid_token_type'),
        );
      }

      // VALIDATE SECRET from database
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

      request.user = {
        id: payload.sub,
        email: payload.email,
        secret: payload.secret,
      };

      return true;
    } catch (error) {
      if (error instanceof Error && error.name === 'TokenExpiredError') {
        throw new UnauthorizedException(
          this.i18n.translate('auth.password_reset_token_expired'),
        );
      }
      throw new UnauthorizedException(
        this.i18n.translate('auth.invalid_password_reset_token'),
      );
    }
  }
}
