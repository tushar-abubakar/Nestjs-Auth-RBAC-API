import { CacheModule } from '@nestjs/cache-manager';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import {
  AcceptLanguageResolver,
  HeaderResolver,
  I18nModule,
  QueryResolver,
} from 'nestjs-i18n';
import * as path from 'path';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AppCacheModule } from './cache/cache.module';
import { AppCacheService } from './cache/cache.service';
import configuration from './config/configuration';
import { AuthModule } from './modules/auth/auth.module';
import { AuthService } from './modules/auth/auth.service';
import { JwtAuthGuard } from './modules/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from './modules/auth/guards/permissions.guard';
import { RolesGuard } from './modules/auth/guards/roles.guard';
import { StepUpGuard } from './modules/auth/guards/step-up.guard';
import { MailModule } from './modules/mail/mail.module';
import { MailService } from './modules/mail/mail.service';
import { PermissionModule } from './modules/permission/permission.module';
import { PermissionService } from './modules/permission/permission.service';
import { RoleModule } from './modules/role/role.module';
import { RoleService } from './modules/role/role.service';
import { TwoFactorModule } from './modules/two-factor/two-factor.module';
import { TwoFactorService } from './modules/two-factor/two-factor.service';
import { PrismaService } from './prisma/prisma.service';

@Module({
  imports: [
    // Global Config Module
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      envFilePath: '.env',
    }),

    // I18nModule with async configuration
    I18nModule.forRootAsync({
      useFactory: (config: ConfigService) => ({
        fallbackLanguage:
          config.getOrThrow<string>('i18n.defaultLanguage') ?? 'en',
        loaderOptions: {
          path: path.join(__dirname, '/i18n/'),
          watch: config.get<string>('app.env') !== 'production',
        },
      }),
      resolvers: [
        { use: QueryResolver, options: ['lang'] },
        AcceptLanguageResolver,
        new HeaderResolver(['x-lang']),
      ],
      inject: [ConfigService],
    }),

    CacheModule.registerAsync({
      isGlobal: true,
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        ttl: config.get<number>('cache.ttl') ?? 300,
        max: config.get<number>('cache.max') ?? 500,
      }),
    }),

    AuthModule,
    MailModule,
    RoleModule,
    PermissionModule,
    AppCacheModule,
    TwoFactorModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    AuthService,
    PrismaService,
    MailService,
    RoleService,
    PermissionService,
    AppCacheService,
    TwoFactorService,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
    {
      provide: APP_GUARD,
      useClass: PermissionsGuard,
    },
    {
      provide: APP_GUARD,
      useClass: StepUpGuard,
    },
  ],
})
export class AppModule {}
