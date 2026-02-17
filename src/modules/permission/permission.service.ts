import { AppCacheService } from '@/cache/cache.service';
import { PrismaService } from '@/prisma/prisma.service';
import { Injectable } from '@nestjs/common';

@Injectable()
export class PermissionService {
  constructor(
    private prisma: PrismaService,
    private cache: AppCacheService,
  ) {}

  async getUserPermissions(userId: string): Promise<string[]> {
    const cacheKey = `permissions:user:${userId}`;

    const cached = await this.cache.get<string[]>(cacheKey);
    if (cached) return cached;

    return await this.fetchPermissionsFromDB(userId);
  }

  private async fetchPermissionsFromDB(userId: string): Promise<string[]> {
    const result = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        role: {
          select: {
            rolePermissions: {
              where: {
                permission: {
                  isActive: true,
                },
              },
              select: {
                permission: {
                  select: {
                    code: true,
                  },
                },
              },
            },
          },
        },
        userPermissions: {
          where: {
            permission: {
              isActive: true,
            },
          },
          select: {
            granted: true,
            permission: {
              select: {
                code: true,
              },
            },
          },
        },
      },
    });

    if (!result) return [];

    // Process permissions
    const rolePermissions = new Set(
      result.role.rolePermissions.map((rp) => rp.permission.code),
    );

    // Apply user-specific overrides
    result.userPermissions.forEach((up) => {
      if (up.granted) {
        rolePermissions.add(up.permission.code);
      } else {
        rolePermissions.delete(up.permission.code);
      }
    });

    return Array.from(rolePermissions);
  }

  async invalidateUserCache(userId: string): Promise<void> {
    await this.cache.del(`permissions:user:${userId}`);
  }

  async hasPermission(
    userId: string,
    permissionCode: string,
  ): Promise<boolean> {
    const permissions = await this.getUserPermissions(userId);
    return permissions.includes(permissionCode);
  }

  async hasAnyPermission(
    userId: string,
    permissionCodes: string[],
  ): Promise<boolean> {
    const permissions = await this.getUserPermissions(userId);
    return permissionCodes.some((code) => permissions.includes(code));
  }

  async hasAllPermissions(
    userId: string,
    permissionCodes: string[],
  ): Promise<boolean> {
    const permissions = await this.getUserPermissions(userId);
    return permissionCodes.every((code) => permissions.includes(code));
  }
}
