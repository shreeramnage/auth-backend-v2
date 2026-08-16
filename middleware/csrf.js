

// export function requireCsrf(req, res, next) {
//   // The frontend must have read the csrfToken cookie itself and echoed it
//   // back here — an attacker's forged cross-site request can't do this,
//   // because it can't read cookies belonging to our origin
//   const headerToken = req.headers['x-csrf-token'];
//   const cookieToken = req.cookies.csrfToken;

//   if (!headerToken || !cookieToken || headerToken !== cookieToken) {
//     return res.status(403).json({ message: 'Invalid or missing CSRF token' });
//   }

//   next();
// }

import crypto from 'crypto';

export function requireCsrf(req, res, next) {
  const headerToken = req.headers['x-csrf-token'];
  const cookieToken = req.cookies.csrfToken;

  if (!headerToken || !cookieToken) {
    return res.status(403).json({ message: 'Invalid or missing CSRF token' });
  }

  const headerBuffer = Buffer.from(headerToken);
  const cookieBuffer = Buffer.from(cookieToken);

  // timingSafeEqual throws on mismatched lengths rather than returning false,
  // so check that first — and only then compare in constant time
  const isValid =
    headerBuffer.length === cookieBuffer.length &&
    crypto.timingSafeEqual(headerBuffer, cookieBuffer);

  if (!isValid) {
    return res.status(403).json({ message: 'Invalid or missing CSRF token' });
  }

  next();
}

