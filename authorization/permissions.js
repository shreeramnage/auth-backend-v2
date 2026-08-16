// The single place role -> permission mappings live. Every route and /me
// both read from this — nothing else in the codebase decides who can do what.
export const ROLE_PERMISSIONS = {
  user: ['posts:read'],
  editor: ['posts:read', 'posts:create', 'posts:update', 'posts:delete'],
  admin: ['posts:read', 'posts:create', 'posts:update', 'posts:delete', 'users:manage'],
};

export function getPermissionsForRole(role) {
  return ROLE_PERMISSIONS[role] || [];
}
