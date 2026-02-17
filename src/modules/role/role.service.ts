import { Injectable } from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';

@Injectable()
export class RoleService {
  constructor(private prisma: PrismaService) {}

  async getUserRole(userId: string): Promise<string | null> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId, isActive: true },
      select: {
        role: {
          select: {
            code: true,
          },
        },
      },
    });

    return user?.role?.code ?? null;
  }

  async hasRole(userId: string, roleCode: string): Promise<boolean> {
    const userRole = await this.getUserRole(userId);
    return userRole === roleCode;
  }

  async hasAnyRole(userId: string, roleCodes: string[]): Promise<boolean> {
    const userRole = await this.getUserRole(userId);
    return userRole ? roleCodes.includes(userRole) : false;
  }
}
