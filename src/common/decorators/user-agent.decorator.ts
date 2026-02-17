import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

export const UserAgent = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): string => {
    const request = ctx.switchToHttp().getRequest<Request>();
    const userAgent = request.headers['user-agent'];
    return typeof userAgent === 'string' ? userAgent : 'unknown';
  },
);
