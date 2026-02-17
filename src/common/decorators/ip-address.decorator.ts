import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

export const IpAddress = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): string => {
    const request = ctx.switchToHttp().getRequest<Request>();

    const forwardedFor = request.headers['x-forwarded-for'];
    const forwardedIp = Array.isArray(forwardedFor)
      ? forwardedFor[0]
      : forwardedFor;

    return (
      forwardedIp?.split(',')[0].trim() ||
      (typeof request.headers['x-real-ip'] === 'string'
        ? request.headers['x-real-ip']
        : null) ||
      request.ip ||
      request.socket?.remoteAddress ||
      'unknown'
    );
  },
);
