import {
  PERMISSIONS_KEY,
  REQUIRE_ALL_PERMISSIONS_KEY,
} from '@/common/decorators/permissions.decorator';
import { AuthUser } from '@/common/types/jwt.type';
import { PermissionService } from '@/modules/permission/permission.service';
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { I18nService } from 'nestjs-i18n';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private permissionService: PermissionService,
    private readonly i18n: I18nService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const requireAll = this.reflector.getAllAndOverride<boolean>(
      REQUIRE_ALL_PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    const request = context
      .switchToHttp()
      .getRequest<Request & { user: AuthUser }>();
    const user = request.user;

    if (!user || !user.id) {
      throw new ForbiddenException(
        this.i18n.translate('auth.errors.insufficient_permissions'),
      );
    }

    let hasPermission: boolean;

    if (requireAll) {
      hasPermission = await this.permissionService.hasAllPermissions(
        user.id,
        requiredPermissions,
      );
    } else {
      hasPermission = await this.permissionService.hasAnyPermission(
        user.id,
        requiredPermissions,
      );
    }

    if (!hasPermission) {
      throw new ForbiddenException(
        this.i18n.translate('auth.errors.insufficient_permissions'),
      );
    }

    return true;
  }
}
