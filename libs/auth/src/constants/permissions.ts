export const PERMISSIONS = {
  // User Management
  USER_CREATE: 'user:create',
  USER_READ: 'user:read',
  USER_UPDATE: 'user:update',
  USER_DELETE: 'user:delete',

  // Post Management
  POST_CREATE: 'post:create',
  POST_READ: 'post:read',
  POST_UPDATE: 'post:update',
  POST_DELETE: 'post:delete',
  POST_MODERATE: 'post:moderate',

  // Event Management
  EVENT_CREATE: 'event:create',
  EVENT_READ: 'event:read',
  EVENT_UPDATE: 'event:update',
  EVENT_DELETE: 'event:delete',

  // Marketplace Management
  LISTING_CREATE: 'listing:create',
  LISTING_READ: 'listing:read',
  LISTING_UPDATE: 'listing:update',
  LISTING_DELETE: 'listing:delete',

  // Neighborhood Management
  NEIGHBORHOOD_CREATE: 'neighborhood:create',
  NEIGHBORHOOD_READ: 'neighborhood:read',
  NEIGHBORHOOD_UPDATE: 'neighborhood:update',
  NEIGHBORHOOD_DELETE: 'neighborhood:delete',
  NEIGHBORHOOD_MODERATE: 'neighborhood:moderate',

  // System Administration
  ADMIN_SYSTEM: 'admin:system',
  ADMIN_USERS: 'admin:users',
  ADMIN_CONTENT: 'admin:content',
  ADMIN_REPORTS: 'admin:reports',

  // Safety & Security
  SAFETY_ALERT_CREATE: 'safety_alert:create',
  SAFETY_ALERT_VERIFY: 'safety_alert:verify',
  SAFETY_ALERT_RESOLVE: 'safety_alert:resolve',

  // Messaging
  MESSAGE_SEND: 'message:send',
  MESSAGE_READ: 'message:read',
  MESSAGE_MODERATE: 'message:moderate',
} as const;

export const ROLES = {
  USER: 'user',
  MODERATOR: 'moderator',
  NEIGHBORHOOD_ADMIN: 'neighborhood_admin',
  ADMIN: 'admin',
  SUPER_ADMIN: 'super_admin',
} as const;

const userPermissions = [
  PERMISSIONS.USER_READ,
  PERMISSIONS.POST_CREATE,
  PERMISSIONS.POST_READ,
  PERMISSIONS.EVENT_CREATE,
  PERMISSIONS.EVENT_READ,
  PERMISSIONS.LISTING_CREATE,
  PERMISSIONS.LISTING_READ,
  PERMISSIONS.NEIGHBORHOOD_READ,
  PERMISSIONS.SAFETY_ALERT_CREATE,
  PERMISSIONS.MESSAGE_SEND,
  PERMISSIONS.MESSAGE_READ,
];

const moderatorPermissions = [
  ...userPermissions,
  PERMISSIONS.POST_MODERATE,
  PERMISSIONS.MESSAGE_MODERATE,
  PERMISSIONS.ADMIN_CONTENT,
  PERMISSIONS.SAFETY_ALERT_VERIFY,
];

const neighborhoodAdminPermissions = [
  ...moderatorPermissions,
  PERMISSIONS.NEIGHBORHOOD_MODERATE,
  PERMISSIONS.USER_UPDATE,
  PERMISSIONS.EVENT_UPDATE,
  PERMISSIONS.EVENT_DELETE,
  PERMISSIONS.POST_DELETE,
  PERMISSIONS.LISTING_DELETE,
  PERMISSIONS.SAFETY_ALERT_RESOLVE,
];

const adminPermissions = [
  ...neighborhoodAdminPermissions,
  PERMISSIONS.ADMIN_USERS,
  PERMISSIONS.ADMIN_REPORTS,
  PERMISSIONS.NEIGHBORHOOD_CREATE,
  PERMISSIONS.NEIGHBORHOOD_UPDATE,
  PERMISSIONS.NEIGHBORHOOD_DELETE,
  PERMISSIONS.USER_DELETE,
];

const superAdminPermissions = [
  ...adminPermissions,
  PERMISSIONS.ADMIN_SYSTEM,
];

export const ROLE_PERMISSIONS: Record<string, string[]> = {
  [ROLES.USER]: userPermissions,
  [ROLES.MODERATOR]: moderatorPermissions,
  [ROLES.NEIGHBORHOOD_ADMIN]: neighborhoodAdminPermissions,
  [ROLES.ADMIN]: adminPermissions,
  [ROLES.SUPER_ADMIN]: superAdminPermissions,
};