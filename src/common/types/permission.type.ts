export interface UserPermissions {
  rolePermissions: string[];
  userSpecificPermissions: Array<{
    code: string;
    granted: boolean;
  }>;
}
