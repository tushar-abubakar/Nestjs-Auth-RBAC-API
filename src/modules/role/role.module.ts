import { PrismaService } from '@/prisma/prisma.service';
import { Module } from '@nestjs/common';
import { RoleService } from './role.service';

@Module({
  providers: [RoleService, PrismaService],
  exports: [RoleService],
})
export class RoleModule {}
