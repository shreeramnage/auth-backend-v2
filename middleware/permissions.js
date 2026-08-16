import User from '../models/User.js';
import { getPermissionsForRole } from '../authorization/permissions.js';

export function requirePermission(permission) {
  return async (req, res, next) => {
    // req.userId was set by requireAuth, which must run before this middleware
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    // Resolve role -> permissions through the one map, then just check membership —
    // this function has no idea what "editor" or "admin" even mean
    const permissions = getPermissionsForRole(user.role);
    if (!permissions.includes(permission)) {
      return res.status(403).json({ message: 'Insufficient permissions' });
    }

    next();
  };
}
