import { PrismaService } from '@/prisma/prisma.service';
import { Module } from '@nestjs/common';
import { PermissionModule } from '../permission/permission.module';
import { TwoFactorController } from './two-factor.controller';
import { TwoFactorService } from './two-factor.service';

@Module({
  imports: [PermissionModule],
  providers: [TwoFactorService, PrismaService],
  controllers: [TwoFactorController],
  exports: [TwoFactorService],
})
export class TwoFactorModule {}
