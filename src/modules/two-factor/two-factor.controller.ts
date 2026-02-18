import { AppCacheService } from '@/cache/cache.service';
import { AUTH_CONSTANTS, CACHE_KEYS } from '@/common/constants/auth.constants';
import { CurrentUser } from '@/common/decorators/current-user.decorator';
import { Permissions } from '@/common/decorators/permissions.decorator';
import { PrismaService } from '@/prisma/prisma.service';
import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { User } from 'generated/prisma/client';
import { I18nService } from 'nestjs-i18n';
import {
  Disable2FADto,
  Enable2FADto,
  RegenerateBackupCodesDto,
} from './dto/two-factor.dto';
import { TwoFactorService } from './two-factor.service';

@Controller('two-factor')
export class TwoFactorController {
  constructor(
    private readonly twoFactorService: TwoFactorService,
    private readonly prisma: PrismaService,
    private readonly i18n: I18nService,
    private readonly config: ConfigService,
    private cache: AppCacheService,
  ) {}

  @Get('setup')
  @Permissions('2fa:manage')
  async setup(
    @CurrentUser('id') userId: string,
  ): Promise<{ message: string; secret: string; qrCode: string }> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });

    if (user?.enable2FA) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.twoFactorAlreadyEnabled'),
      );
    }

    const { secret, otpauth } = this.twoFactorService.generateSecret(
      user!.email,
    );
    const qrCode = await this.twoFactorService.generateQrCode(otpauth);

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorSecret: secret,
        enable2FA: false,
      },
    });

    return {
      message: this.i18n.translate('auth.success.twoFactorSetupInitiated'),
      secret,
      qrCode,
    };
  }

  @Post('enable')
  @Permissions('2fa:manage')
  @HttpCode(HttpStatus.OK)
  async enable(
    @CurrentUser('id') userId: string,
    @Body() dto: Enable2FADto,
  ): Promise<{ message: string; backupCodes: string[] }> {
    const preferences = await this.verifyAndGet2FAPreferences(
      userId,
      dto.code,
      {
        mustBeEnabled: false,
        requireSecret: true,
      },
    );

    const backupCodesCount =
      this.config.get<number>('twoFactor.backupCodeCount') ?? 10;
    const { plainCodes, hashedCodes } =
      await this.twoFactorService.generateBackupCodes(backupCodesCount);

    await this.prisma.user.update({
      where: { id: userId },
      data: { enable2FA: true, backupCodes: hashedCodes },
    });

    await this.cache.del(CACHE_KEYS.TWO_FACTOR_ATTEMPTS(userId));

    // suppress unused warning — preferences fetched for side-effect of TOTP check
    void preferences;

    return {
      message: this.i18n.translate('auth.success.twoFactorEnabled'),
      backupCodes: plainCodes,
    };
  }

  @Delete('disable')
  @Permissions('2fa:manage')
  @HttpCode(HttpStatus.OK)
  async disable(
    @CurrentUser('id') userId: string,
    @Body() dto: Disable2FADto,
  ): Promise<{ message: string }> {
    await this.verifyAndGet2FAPreferences(userId, dto.code, {
      mustBeEnabled: true,
      requireSecret: true,
    });

    await this.prisma.user.update({
      where: { id: userId },
      data: { enable2FA: false, twoFactorSecret: null, backupCodes: [] },
    });

    await this.cache.del(CACHE_KEYS.TWO_FACTOR_ATTEMPTS(userId));

    return { message: this.i18n.translate('auth.success.twoFactorDisabled') };
  }

  @Post('regenerate-backup-codes')
  @Permissions('2fa:manage')
  @HttpCode(HttpStatus.OK)
  async regenerateBackupCodes(
    @CurrentUser('id') userId: string,
    @Body() dto: RegenerateBackupCodesDto,
  ): Promise<{ message: string; backupCodes: string[] }> {
    await this.verifyAndGet2FAPreferences(userId, dto.code, {
      mustBeEnabled: true,
      requireSecret: true,
    });

    const { plainCodes, hashedCodes } =
      await this.twoFactorService.generateBackupCodes(
        AUTH_CONSTANTS.BACKUP_CODES_COUNT,
      );

    await this.prisma.user.update({
      where: { id: userId },
      data: { backupCodes: hashedCodes },
    });

    await this.cache.del(CACHE_KEYS.TWO_FACTOR_ATTEMPTS(userId));

    return {
      message: this.i18n.translate('auth.success.backupCodesRegenerated'),
      backupCodes: plainCodes,
    };
  }

  @Get('backup-codes-count')
  @Permissions('2fa:manage')
  async getBackupCodesCount(
    @CurrentUser('id') userId: string,
  ): Promise<{ count: number }> {
    const preferences = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { backupCodes: true },
    });

    return { count: preferences?.backupCodes?.length ?? 0 };
  }

  @Get('status')
  @Permissions('2fa:manage')
  async getStatus(
    @CurrentUser('id') userId: string,
  ): Promise<{ enabled: boolean; backupCodesCount: number }> {
    const preferences = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { enable2FA: true, backupCodes: true },
    });

    return {
      enabled: preferences?.enable2FA ?? false,
      backupCodesCount: preferences?.backupCodes?.length ?? 0,
    };
  }

  // ============================================================================
  // PRIVATE — MERGED 2FA GUARD + PREFERENCES FETCH
  // ============================================================================

  /**
   * Consolidates the previously separate `check2FAAttempts`, `increment2FAAttempts`
   * calls and the repeated `findUnique → verifyToken → increment-on-fail` pattern
   * that existed in `enable`, `disable`, and `regenerateBackupCodes`.
   *
   * Steps:
   *  1. Check the lockout counter — throw if exceeded.
   *  2. Fetch user preferences and validate the expected 2FA state.
   *  3. Verify the submitted TOTP code — increment counter and throw on failure.
   *
   * On success the preferences object is returned so callers can use it if needed.
   * The lockout cache key is NOT cleared here — each successful action clears it
   * individually after its own DB write, maintaining the existing behaviour.
   *
   * @param mustBeEnabled  true  → 2FA must already be active (disable / regenerate)
   *                       false → 2FA must NOT be active yet (enable)
   * @param requireSecret  whether `twoFactorSecret` must be present
   */
  private async verifyAndGet2FAPreferences(
    userId: string,
    code: string,
    options: { mustBeEnabled: boolean; requireSecret: boolean },
  ): Promise<User> {
    const attempts =
      (await this.cache.get<number>(CACHE_KEYS.TWO_FACTOR_ATTEMPTS(userId))) ??
      0;

    if (attempts >= AUTH_CONSTANTS.MAX_2FA_ATTEMPTS) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.twoFactorLockedOut'),
      );
    }

    const preferences = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (
      options.mustBeEnabled &&
      (!preferences?.enable2FA || !preferences.twoFactorSecret)
    ) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.twoFactorNotEnabled'),
      );
    }

    if (
      !options.mustBeEnabled &&
      options.requireSecret &&
      !preferences?.twoFactorSecret
    ) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.twoFactorSetupRequired'),
      );
    }

    const secret = preferences?.twoFactorSecret;
    if (!secret) {
      throw new BadRequestException(
        this.i18n.translate('auth.errors.twoFactorSetupRequired'),
      );
    }

    const isValid = this.twoFactorService.verifyToken(code, secret);

    if (!isValid) {
      await this.cache.increment(
        CACHE_KEYS.TWO_FACTOR_ATTEMPTS(userId),
        AUTH_CONSTANTS.TWO_FACTOR_LOCKOUT_DURATION / 1000,
      );
      throw new BadRequestException(
        this.i18n.translate('auth.errors.invalid2faCode'),
      );
    }

    return preferences;
  }
}
