import { CustomDecorator, SetMetadata } from '@nestjs/common';

export const PERMISSIONS_KEY = 'permissions';
export const Permissions = (
  ...permissions: string[]
): CustomDecorator<string> => SetMetadata(PERMISSIONS_KEY, permissions);

export const REQUIRE_ALL_PERMISSIONS_KEY = 'requireAllPermissions';
export const RequireAllPermissions = (): CustomDecorator<string> =>
  SetMetadata(REQUIRE_ALL_PERMISSIONS_KEY, true);
