import { CustomDecorator, SetMetadata } from '@nestjs/common';

export const STEP_UP_KEY = 'requiresStepUp';
export const RequireStepUp = (): CustomDecorator<string> =>
  SetMetadata(STEP_UP_KEY, true);
