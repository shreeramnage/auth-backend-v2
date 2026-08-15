export function requireCsrf(req, res, next) {
  // The frontend must have read the csrfToken cookie itself and echoed it
  // back here — an attacker's forged cross-site request can't do this,
  // because it can't read cookies belonging to our origin
  const headerToken = req.headers['x-csrf-token'];
  const cookieToken = req.cookies.csrfToken;

  if (!headerToken || !cookieToken || headerToken !== cookieToken) {
    return res.status(403).json({ message: 'Invalid or missing CSRF token' });
  }

  next();
}
