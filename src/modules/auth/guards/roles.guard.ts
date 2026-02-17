import { ROLES_KEY } from '@/common/decorators/roles.decorator';
import { AuthUser } from '@/common/types/jwt.type';
import { RoleService } from '@/modules/role/role.service';
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { I18nService } from 'nestjs-i18n';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private roleService: RoleService,
    private readonly i18n: I18nService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context
      .switchToHttp()
      .getRequest<Request & { user: AuthUser }>();
    const user = request.user;

    if (!user || !user.id) {
      throw new ForbiddenException(
        this.i18n.translate('auth.errors.insufficient_permissions'),
      );
    }

    const hasRole = await this.roleService.hasAnyRole(user.id, requiredRoles);

    if (!hasRole) {
      throw new ForbiddenException(
        this.i18n.translate('auth.errors.insufficient_permissions'),
      );
    }

    return true;
  }
}
