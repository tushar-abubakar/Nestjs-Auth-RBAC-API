import { PrismaPg } from '@prisma/adapter-pg';
import { hash } from 'argon2';
import {
  Permission,
  Prisma,
  PrismaClient,
  Role,
  User,
} from 'generated/prisma/client';

const pool = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma = new PrismaClient({ adapter: pool });

interface PermissionData {
  code: string;
  name: string;
  module: string;
  description: string;
}

async function main(): Promise<void> {
  console.log('Starting database seeding...');

  // Create Permissions
  const permissions: PermissionData[] = [
    // User Management
    {
      code: 'user:read',
      name: 'Read Users',
      module: 'user',
      description: 'View user information',
    },
    {
      code: 'user:create',
      name: 'Create Users',
      module: 'user',
      description: 'Create new users',
    },
    {
      code: 'user:update',
      name: 'Update Users',
      module: 'user',
      description: 'Update user information',
    },
    {
      code: 'user:delete',
      name: 'Delete Users',
      module: 'user',
      description: 'Delete users',
    },
    {
      code: 'user:manage',
      name: 'Manage Users',
      module: 'user',
      description: 'Full user management',
    },

    // Profile Management
    {
      code: 'profile:read',
      name: 'Read Profile',
      module: 'profile',
      description: 'View own profile',
    },
    {
      code: 'profile:update',
      name: 'Update Profile',
      module: 'profile',
      description: 'Update own profile',
    },

    // Session Management
    {
      code: 'session:read',
      name: 'Read Sessions',
      module: 'session',
      description: 'View sessions',
    },
    {
      code: 'session:delete',
      name: 'Delete Sessions',
      module: 'session',
      description: 'Delete sessions',
    },

    // Admin Operations
    {
      code: 'admin:access',
      name: 'Admin Access',
      module: 'admin',
      description: 'Access admin panel',
    },
    {
      code: 'admin:users:read',
      name: 'Admin Read Users',
      module: 'admin',
      description: 'View all users in admin',
    },
    {
      code: 'admin:users:update',
      name: 'Admin Update Users',
      module: 'admin',
      description: 'Update users in admin',
    },
    {
      code: 'admin:users:delete',
      name: 'Admin Delete Users',
      module: 'admin',
      description: 'Delete users in admin',
    },

    // Role & Permission Management
    {
      code: 'role:read',
      name: 'Read Roles',
      module: 'role',
      description: 'View roles',
    },
    {
      code: 'role:create',
      name: 'Create Roles',
      module: 'role',
      description: 'Create new roles',
    },
    {
      code: 'role:update',
      name: 'Update Roles',
      module: 'role',
      description: 'Update roles',
    },
    {
      code: 'role:delete',
      name: 'Delete Roles',
      module: 'role',
      description: 'Delete roles',
    },
    {
      code: 'permission:read',
      name: 'Read Permissions',
      module: 'permission',
      description: 'View permissions',
    },
    {
      code: 'permission:assign',
      name: 'Assign Permissions',
      module: 'permission',
      description: 'Assign permissions to users/roles',
    },

    // 2FA Management
    {
      code: '2fa:manage',
      name: 'Manage 2FA',
      module: '2fa',
      description: 'Manage two-factor authentication',
    },
  ];

  const createdPermissions: Permission[] = [];

  for (const permission of permissions) {
    const upsertArgs: Prisma.PermissionUpsertArgs = {
      where: { code: permission.code },
      update: {},
      create: {
        code: permission.code,
        name: permission.name,
        module: permission.module,
        description: permission.description,
        isSystem: true,
      },
    };

    const created: Permission = await prisma.permission.upsert(upsertArgs);
    createdPermissions.push(created);
  }

  console.log(`Created ${createdPermissions.length} permissions`);

  // Create Roles
  const adminRoleArgs: Prisma.RoleUpsertArgs = {
    where: { code: 'ADMIN' },
    update: {},
    create: {
      code: 'ADMIN',
      name: 'Administrator',
      description: 'Full system access',
      isSystem: true,
    },
  };
  const adminRole: Role = await prisma.role.upsert(adminRoleArgs);

  const editorRoleArgs: Prisma.RoleUpsertArgs = {
    where: { code: 'EDITOR' },
    update: {},
    create: {
      code: 'EDITOR',
      name: 'Editor',
      description: 'Content editing access',
      isSystem: true,
    },
  };
  const editorRole: Role = await prisma.role.upsert(editorRoleArgs);

  const userRoleArgs: Prisma.RoleUpsertArgs = {
    where: { code: 'USER' },
    update: {},
    create: {
      code: 'USER',
      name: 'User',
      description: 'Basic user access',
      isSystem: true,
    },
  };
  const userRole: Role = await prisma.role.upsert(userRoleArgs);

  console.log('Created roles: ADMIN, EDITOR, USER');

  // Assign permissions to Admin role (all permissions)
  let adminPermissionsCount: number = 0;
  for (const permission of createdPermissions) {
    const rolePermArgs: Prisma.RolePermissionUpsertArgs = {
      where: {
        roleId_permissionId: {
          roleId: adminRole.id,
          permissionId: permission.id,
        },
      },
      update: {},
      create: {
        roleId: adminRole.id,
        permissionId: permission.id,
      },
    };
    await prisma.rolePermission.upsert(rolePermArgs);
    adminPermissionsCount++;
  }
  console.log(`Assigned ${adminPermissionsCount} permissions to ADMIN role`);

  // Assign permissions to Editor role
  const editorPermissionCodes: string[] = [
    'user:read',
    'profile:read',
    'profile:update',
    'session:read',
    'session:delete',
    '2fa:manage',
  ];

  let editorPermissionsCount: number = 0;
  for (const code of editorPermissionCodes) {
    const permission: Permission | undefined = createdPermissions.find(
      (p) => p.code === code,
    );
    if (permission) {
      const rolePermArgs: Prisma.RolePermissionUpsertArgs = {
        where: {
          roleId_permissionId: {
            roleId: editorRole.id,
            permissionId: permission.id,
          },
        },
        update: {},
        create: {
          roleId: editorRole.id,
          permissionId: permission.id,
        },
      };
      await prisma.rolePermission.upsert(rolePermArgs);
      editorPermissionsCount++;
    }
  }
  console.log(`Assigned ${editorPermissionsCount} permissions to EDITOR role`);

  // Assign permissions to User role
  const userPermissionCodes: string[] = [
    'profile:read',
    'profile:update',
    'session:read',
    'session:delete',
    '2fa:manage',
  ];

  let userPermissionsCount: number = 0;
  for (const code of userPermissionCodes) {
    const permission: Permission | undefined = createdPermissions.find(
      (p) => p.code === code,
    );
    if (permission) {
      const rolePermArgs: Prisma.RolePermissionUpsertArgs = {
        where: {
          roleId_permissionId: {
            roleId: userRole.id,
            permissionId: permission.id,
          },
        },
        update: {},
        create: {
          roleId: userRole.id,
          permissionId: permission.id,
        },
      };
      await prisma.rolePermission.upsert(rolePermArgs);
      userPermissionsCount++;
    }
  }
  console.log(`Assigned ${userPermissionsCount} permissions to USER role`);

  // Create default admin user
  const hashedPassword: string = await hash('Admin@123');

  const adminUserArgs: Prisma.UserUpsertArgs = {
    where: { email: 'admin@example.com' },
    update: {},
    create: {
      firstName: 'Admin',
      lastName: 'User',
      username: 'admin',
      email: 'admin@example.com',
      password: hashedPassword,
      isEmailVerified: true,
      roleId: adminRole.id,
    },
  };

  const adminUser: User = await prisma.user.upsert(adminUserArgs);

  console.log(`Created admin user: ${adminUser.email}`);
  console.log('\nDatabase seeding completed successfully!');
}

main()
  .catch((error: Error) => {
    console.error('Seeding failed:', error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
