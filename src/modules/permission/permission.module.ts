import { AppCacheService } from '@/cache/cache.service';
import { PrismaService } from '@/prisma/prisma.service';
import { Module } from '@nestjs/common';
import { PermissionService } from './permission.service';

@Module({
  providers: [PermissionService, PrismaService, AppCacheService],
  exports: [PermissionService],
})
export class PermissionModule {}
