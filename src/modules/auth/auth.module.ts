import { AppCacheService } from '@/cache/cache.service';
import { PermissionModule } from '@/modules/permission/permission.module';
import { PrismaService } from '@/prisma/prisma.service';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { StringValue } from 'ms';
import { MailModule } from '../mail/mail.module';
import { MailService } from '../mail/mail.service';
import { TwoFactorService } from '../two-factor/two-factor.service';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { FlowGuard } from './guards/auth-flow';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        global: true,
        secret: config.get<string>('jwt.secret', ''),
        signOptions: {
          expiresIn: config.get<StringValue>('jwt.expiresIn', '1d'),
        },
      }),
    }),
    PassportModule,
    MailModule,
    PermissionModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PrismaService,
    MailService,
    JwtStrategy,
    AppCacheService,
    TwoFactorService,
    FlowGuard,
  ],
  exports: [AuthService, JwtModule, FlowGuard],
})
export class AuthModule {}
