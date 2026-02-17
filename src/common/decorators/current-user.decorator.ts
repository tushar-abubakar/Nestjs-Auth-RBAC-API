import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { AuthUser } from '../types/jwt.type';

export const CurrentUser = createParamDecorator(
  (
    data: keyof AuthUser | undefined,
    ctx: ExecutionContext,
  ): AuthUser | AuthUser[keyof AuthUser] | undefined => {
    const request = ctx.switchToHttp().getRequest<{ user: AuthUser }>();
    const user = request.user;

    return data ? user?.[data] : user;
  },
);
