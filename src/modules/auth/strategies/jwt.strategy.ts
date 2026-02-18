import { AuthUser, JwtPayload, TokenType } from '@/common/types/jwt.type';
import { PermissionService } from '@/modules/permission/permission.service';
import { PrismaService } from '@/prisma/prisma.service';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { I18nService } from 'nestjs-i18n';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly i18n: I18nService,
    private permissionService: PermissionService,
    private prisma: PrismaService,
    configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('jwt.secret') ?? '',
    });
  }

  async validate(payload: JwtPayload): Promise<AuthUser> {
    // Only allow ACCESS tokens for regular authentication
    if (payload.type !== TokenType.ACCESS) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.invalid_token_type'),
      );
    }

    // Fetch fresh user data including role
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub, isActive: true },
      include: { role: true },
    });

    if (!user) {
      throw new UnauthorizedException(
        this.i18n.translate('auth.user_not_found_or_inactive'),
      );
    }

    // Verify session if sessionId is present
    if (payload.sessionId) {
      const session = await this.prisma.session.findUnique({
        where: { id: payload.sessionId },
      });

      if (!session || session.expiredAt < new Date()) {
        throw new UnauthorizedException(
          this.i18n.translate('auth.session_expired_or_invalid'),
        );
      }
    }

    const permissions: string[] =
      await this.permissionService.getUserPermissions(payload.sub);

    return {
      id: payload.sub,
      sessionId: payload.sessionId,
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      roleCode: user.role.code,
      permissions,
    };
  }
}
