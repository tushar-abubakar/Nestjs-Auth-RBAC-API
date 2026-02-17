import { AppCacheService } from '@/cache/cache.service';
import { CACHE_KEYS } from '@/common/constants/auth.constants';
import { STEP_UP_KEY } from '@/common/decorators/step-up.decorator';
import { AuthUser } from '@/common/types/jwt.type';
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { I18nService } from 'nestjs-i18n';

@Injectable()
export class StepUpGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private cache: AppCacheService,
    private readonly i18n: I18nService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiresStepUp = this.reflector.getAllAndOverride<boolean>(
      STEP_UP_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiresStepUp) {
      return true;
    }

    const request = context
      .switchToHttp()
      .getRequest<Request & { user: AuthUser }>();
    const user = request.user;

    if (!user || !user.id || !user.sessionId) {
      throw new ForbiddenException(
        this.i18n.translate('auth.errors.step_up_required'),
      );
    }

    const stepUpVerified = await this.cache.get<boolean>(
      CACHE_KEYS.STEP_UP_VERIFIED(user.id, user.sessionId),
    );

    if (!stepUpVerified) {
      throw new ForbiddenException(
        this.i18n.translate('auth.errors.step_up_required'),
      );
    }

    return true;
  }
}
