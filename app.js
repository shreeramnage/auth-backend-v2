import 'dotenv/config';
import express from 'express';
import bcrypt from 'bcrypt';
import helmet from 'helmet';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import rateLimit from 'express-rate-limit';
import User from './models/User.js';
import { requireAuth } from './middleware/auth.js';
import crypto from 'crypto';
import RefreshToken from './models/RefreshToken.js';
import cookieParser from 'cookie-parser';
import { requireCsrf } from './middleware/csrf.js';
import { validate } from './middleware/validate.js';
import { changePasswordSchema, forgotPasswordSchema, loginSchema, registerSchema, resetPasswordSchema } from './validators/authSchemas.js';
import { sendPasswordResetEmail, sendVerificationEmail } from './utils/mailer.js';
import { getPermissionsForRole } from './authorization/permissions.js';
import Post from './models/Post.js';
import { requirePermission } from './middleware/permissions.js';
import { postSchema } from './validators/postSchemas.js';
import logger from './utils/logger.js';

const requiredEnvVars = ['MONGO_URI', 'JWT_SECRET', 'REFRESH_TOKEN_SECRET', 'ALLOWED_ORIGINS'];

for (const key of requiredEnvVars) {
    if (!process.env[key]) {
        console.error(`Missing required environment variable: ${key}`);
        process.exit(1);
    }
}


const app = express();
app.set('trust proxy', 1);

app.use(helmet());
app.use(express.json());
app.use(cookieParser()); // lets req.cookies read the raw Cookie header as an object


const allowedOrigins = process.env.ALLOWED_ORIGINS.split(',');

app.use(cors({
    origin: (origin, callback) => {
        // No Origin header means a non-browser caller (curl, Postman, server-to-server) — allow it
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, // required for cookies to work once a browser frontend calls this API
}));



// Strict — login/register are rare, deliberate actions; no legitimate reason to hit these often
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    // windowMs: 30 * 1000,
    max: 10,
    message: { message: 'Too many attempts, please try again later' },
});

// Looser — refresh happens automatically and often during normal use
const refreshLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    message: { message: 'Too many requests, please try again later' },
});


app.get('/', (req, res) => {
    res.send('Server is alive');
});

app.post('/register', authLimiter, validate(registerSchema), async (req, res) => {
    const { email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
        email,
        password: hashedPassword,
    });

    // A purpose-locked, short-lived JWT — signature proves it's really from us,
    // 'purpose' stops it being reused for anything other than email verification
    const verificationToken = jwt.sign(
        { userId: user._id, purpose: 'verify-email' },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    // Store only the hash, same single-use pattern as refresh tokens —
    // consuming it later will clear this field so it can't be replayed
    user.emailVerificationTokenHash = crypto.createHash('sha256').update(verificationToken).digest('hex');
    await user.save();

    // Standing in for "send an email" — logging the raw token so you can copy it
    console.log('Verification token for', email, ':', verificationToken);
    // Actually send it — this is the real inbox now, not a console log
    //   await sendVerificationEmail(user.email, verificationToken);
    // so the suite is fast and doesn't depend on an external service succeeding
    if (process.env.NODE_ENV !== 'test') {
        await sendVerificationEmail(user.email, verificationToken);
    }

    // res.status(201).json({
    //     id: user._id,
    //     email: user.email,
    //     message: 'Registration successful. Check your email to verify your account.',
    // });
    res.status(201).json({
        id: user._id,
        email: user.email,
        message: 'Registration successful. Check your email to verify your account.',
        // Only in test mode: expose the raw token, since a test can't read a real inbox
        ...(process.env.NODE_ENV === 'test' && { verificationToken }),
    });

});


app.post('/verify-email', async (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ message: 'Token is required' });
    }

    // Confirm the signature and expiry first — cheap, no DB hit yet
    let payload;
    try {
        payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
        return res.status(400).json({ message: 'Invalid or expired token' });
    }

    // Purpose lock — this token must have been minted specifically for email verification
    if (payload.purpose !== 'verify-email') {
        return res.status(400).json({ message: 'Invalid token' });
    }

    const user = await User.findById(payload.userId);
    if (!user) {
        return res.status(400).json({ message: 'Invalid token' });
    }

    // Single-use check: hash what was presented, compare to the one stored hash.
    // If it's already null (used before) or doesn't match, reject.
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    if (user.emailVerificationTokenHash !== tokenHash) {
        return res.status(400).json({ message: 'Invalid or already-used token' });
    }

    // Consume it: flip the flag, clear the hash so this exact token can never work again
    user.emailVerified = true;
    user.emailVerificationTokenHash = null;
    await user.save();

    res.json({ message: 'Email verified' });
});


// Login 1
// app.post('/login', async (req, res) => {
//   const { email, password } = req.body;

//   const user = await User.findOne({ email });
//   if (!user) {
//     return res.status(401).json({ message: 'Invalid credentials' });
//   }

//   const isMatch = await bcrypt.compare(password, user.password);
//   if (!isMatch) {
//     return res.status(401).json({ message: 'Invalid credentials' });
//   }

//   const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
//     expiresIn: '15m',
//   });

//   res.json({ token });
// });

// Login 2
app.post('/login', authLimiter, validate(loginSchema), async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check the lock BEFORE spending time on bcrypt.compare — a locked account
    // stays locked no matter how correct the password guess is
    if (user.lockUntil && user.lockUntil > new Date()) {
        return res.status(429).json({ message: 'Account locked due to too many failed attempts, try again later' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    // if (!isMatch) {
    //   return res.status(401).json({ message: 'Invalid credentials' });
    // }

    if (!isMatch) {
        // Wrong password: count it, and lock the account once the count crosses the line
        user.failedLoginAttempts += 1;
        if (user.failedLoginAttempts >= 5) {
            // user.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
            user.lockUntil = new Date(Date.now() + 15 * 1000); // was 15 * 60 * 1000 — 15 seconds for testing
            user.failedLoginAttempts = 0;
        }
        await user.save();
        logger.warn({ event: 'login_failed', email }, 'Failed login attempt');
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Correct password: clear any prior failure history
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    await user.save();
    logger.info({ event: 'login_success', userId: user._id, email }, 'User logged in');


    // const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    //     expiresIn: '15m',
    // });
    const accessToken = jwt.sign({ userId: user._id, jti: crypto.randomUUID() }, process.env.JWT_SECRET, {
        expiresIn: '15m',
    });


    // One new random ID per login — ties every future rotation of this
    // refresh token back to this same original session/device
    const family = crypto.randomUUID();

    // const refreshToken = jwt.sign({ userId: user._id, family }, process.env.REFRESH_TOKEN_SECRET, {
    //     expiresIn: '7d',
    // });
    const refreshToken = jwt.sign({ userId: user._id, family, jti: crypto.randomUUID() }, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: '7d',
    });


    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await RefreshToken.create({
        userId: user._id,
        family,
        tokenHash,
        expiresAt,
        userAgent: req.headers['user-agent'] || 'unknown',
        ip: req.ip,
        createdAt: new Date(),
        lastUsedAt: new Date(),
    });

    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'strict',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // A random value the frontend must read and echo back as a header on
    // state-changing requests — proves the request came from our own JS,
    // not a forged cross-site request that only got the cookie sent automatically
    const csrfToken = crypto.randomBytes(32).toString('hex');

    res.cookie('csrfToken', csrfToken, {
        httpOnly: false, // deliberately readable by JS — that's the whole point
        secure: false,
        sameSite: 'strict',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });


    res.json({ accessToken });
});

// Rfresh
// app.post('/refresh', async (req, res) => {
//   // Pull the refresh token out of the httpOnly cookie cookie-parser just decoded for us
//   const refreshToken = req.cookies.refreshToken;

//   if (!refreshToken) {
//     return res.status(401).json({ message: 'No refresh token provided' });
//   }

//   // Check the signature is authentic and not expired — pure math, no DB hit yet
//   let payload;
//   try {
//     payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
//   } catch (err) {
//     return res.status(401).json({ message: 'Invalid refresh token' });
//   }

//   // Re-hash the raw token the same way we did at login, then look it up in the DB —
//   // this is what makes it revocable eventhe signature is still technically valid
//   const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
//   const stored = await RefreshToken.findOne({ tokenHash });

//   if (!stored) {
//     return res.status(401).json({ message: 'Refresh token not recognized' });
//   }

//   // Everything checked out — mint a fresh short-lived access token and hand it back
//   const accessToken = jwt.sign({ userId: payload.userId }, process.env.JWT_SECRET, {
//     expiresIn: '15m',
//   });

//   res.json({ accessToken });
// });
app.post('/refresh', refreshLimiter, requireCsrf, async (req, res) => {
    // Pull the refresh token out of the httpOnly cookie
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ message: 'No refresh token provided' });
    }

    // Confirm the signature is authentic and not expired, and recover userId + family
    let payload;
    try {
        payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    } catch (err) {
        return res.status(401).json({ message: 'Invalid refresh token' });
    }

    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const stored = await RefreshToken.findOne({ tokenHash });

    if (!stored) {
        // No row for this token — it must have already been rotated out and is
        // now being replayed. Treat as theft: kill every token in this family.
        await RefreshToken.deleteMany({ userId: payload.userId, family: payload.family });
        logger.warn({ event: 'refresh_reuse_detected', userId: payload.userId, family: payload.family }, 'Refresh token reuse detected — session revoked');
        return res.status(401).json({ message: 'Refresh token reuse detected — session revoked' });
    }

    // Legitimate single use: remove the token that was just presented...
    await RefreshToken.deleteOne({ _id: stored._id });

    // ...and issue a brand new one in the same family, continuing the chain
    // createdAt and userAgent carry over from the old doc — this is still
    // "the same session" from the user's point of view, just a rotated token
    // const newRefreshToken = jwt.sign(
    //     { userId: payload.userId, family: payload.family },
    //     process.env.REFRESH_TOKEN_SECRET,
    //     { expiresIn: '7d' }
    // );
    const newRefreshToken = jwt.sign(
        { userId: payload.userId, family: payload.family, jti: crypto.randomUUID() },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
    );

    const newTokenHash = crypto.createHash('sha256').update(newRefreshToken).digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await RefreshToken.create({
        userId: payload.userId,
        family: payload.family,
        tokenHash: newTokenHash,
        expiresAt,
        userAgent: stored.userAgent,
        ip: req.ip,
        createdAt: stored.createdAt,
        lastUsedAt: new Date(),
    });

    logger.info({ event: 'token_refreshed', userId: payload.userId, family: payload.family }, 'Refresh token rotated');


    res.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'strict',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // Rotate the CSRF token too, so it stays paired with the current refresh token
    const newCsrfToken = crypto.randomBytes(32).toString('hex');
    res.cookie('csrfToken', newCsrfToken, {
        httpOnly: false,
        secure: false,
        sameSite: 'strict',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });


    // const accessToken = jwt.sign({ userId: payload.userId }, process.env.JWT_SECRET, {
    //     expiresIn: '15m',
    // });
    const accessToken = jwt.sign({ userId: payload.userId, jti: crypto.randomUUID() }, process.env.JWT_SECRET, {
        expiresIn: '15m',
    });


    res.json({ accessToken });
});

app.post('/logout', requireCsrf, async (req, res) => {
    // Grab the refresh token from the cookie so we know which DB record to remove
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
        // Same hash we stored at login — delete that row so this token can never be refreshed again
        const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
        await RefreshToken.deleteOne({ tokenHash });
    }

    // Tell the browser to drop the cookie too — needs the same options used to set it,
    // or the browser won't recognize it as the same cookie to clear
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: false,
        sameSite: 'strict',
        path: '/',
    });

    logger.info({ event: 'logout' }, 'User logged out');

    res.json({ message: 'Logged out' });
});

// app.get('/me', requireAuth, (req, res) => {
//   res.json({ userId: req.userId });
// });
app.get('/me', requireAuth, async (req, res) => {
    // Look up the current role fresh, same reasoning as requirePermission —
    // this response should reflect reality right now, not what the JWT was told at login
    const user = await User.findById(req.userId);

    res.json({
        userId: user._id,
        email: user.email,
        role: user.role,
        permissions: getPermissionsForRole(user.role),
    });
});


app.post('/forgot-password', validate(forgotPasswordSchema), async (req, res) => {
    const { email } = req.body;

    const user = await User.findOne({ email });

    // Only actually do anything if the account exists — but respond identically either way,
    // so the response itself never reveals whether that email is registered
    if (user) {
        const resetToken = jwt.sign(
            { userId: user._id, purpose: 'password-reset' },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );

        user.passwordResetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        await user.save();

        await sendPasswordResetEmail(user.email, resetToken);
    }

    res.json({ message: 'If that email is registered, a reset link has been sent' });
});

app.post('/reset-password', validate(resetPasswordSchema), async (req, res) => {
    const { token, newPassword } = req.body;

    let payload;
    try {
        payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
        return res.status(400).json({ message: 'Invalid or expired token' });
    }

    if (payload.purpose !== 'password-reset') {
        return res.status(400).json({ message: 'Invalid token' });
    }

    const user = await User.findById(payload.userId);
    if (!user) {
        return res.status(400).json({ message: 'Invalid token' });
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    if (user.passwordResetTokenHash !== tokenHash) {
        return res.status(400).json({ message: 'Invalid or already-used token' });
    }

    // Consume it: set the new password, clear the hash so this exact token dies here
    user.password = await bcrypt.hash(newPassword, 10);
    user.passwordResetTokenHash = null;
    await user.save();

    res.json({ message: 'Password reset successful' });
});

app.post('/change-password', requireAuth, validate(changePasswordSchema), async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.userId);

    // Confirm they actually know the current password before allowing a change —
    // otherwise a stolen access token alone could be used to lock the real owner out
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
        return res.status(401).json({ message: 'Current password is incorrect' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    // Kill every session for this user, everywhere — not just this one.
    // A password change is often a response to suspected compromise, so
    // leaving any old refresh token alive would defeat the point of it
    await RefreshToken.deleteMany({ userId: user._id });

    res.json({ message: 'Password changed. All sessions have been logged out.' });
});

app.get('/users', requireAuth, requirePermission('users:manage'), async (req, res) => {
    const users = await User.find().select('-password -emailVerificationTokenHash -passwordResetTokenHash');
    res.json(users);
});


// Post related routes
app.post('/posts', requireAuth, requirePermission('posts:create'), validate(postSchema), async (req, res) => {
    const { title, body } = req.body;

    // authorId comes from the verified token, never from the request body —
    // otherwise anyone could create a post claiming to be someone else
    const post = await Post.create({ title, body, authorId: req.userId });

    res.status(201).json(post);
});

app.get('/posts', requireAuth, requirePermission('posts:read'), async (req, res) => {
    const posts = await Post.find();
    res.json(posts);
});

app.get('/posts/:id', requireAuth, requirePermission('posts:read'), async (req, res) => {
    const post = await Post.findById(req.params.id);
    if (!post) {
        return res.status(404).json({ message: 'Post not found' });
    }
    res.json(post);
});

app.put('/posts/:id', requireAuth, requirePermission('posts:update'), validate(postSchema), async (req, res) => {
    const { title, body } = req.body;

    const post = await Post.findByIdAndUpdate(
        req.params.id,
        { title, body },
        { new: true } // return the updated document, not the pre-update one
    );

    if (!post) {
        return res.status(404).json({ message: 'Post not found' });
    }
    res.json(post);
});

app.delete('/posts/:id', requireAuth, requirePermission('posts:delete'), async (req, res) => {
    const post = await Post.findByIdAndDelete(req.params.id);
    if (!post) {
        return res.status(404).json({ message: 'Post not found' });
    }
    res.json({ message: 'Post deleted' });
});



// Session related routes
app.get('/sessions', requireAuth, async (req, res) => {
    // Never expose tokenHash — it's the one field that would let someone
    // impersonate this session if it ever leaked
    const sessions = await RefreshToken.find({ userId: req.userId }).select('-tokenHash');
    res.json(sessions);
});

app.delete('/sessions/:id', requireAuth, async (req, res) => {
    // Scoped to req.userId, not just :id — this is what stops one user from
    // revoking a session that isn't theirs, even if they know its id
    const session = await RefreshToken.findOneAndDelete({
        _id: req.params.id,
        userId: req.userId,
    });

    if (!session) {
        return res.status(404).json({ message: 'Session not found' });
    }

    res.json({ message: 'Session revoked' });
});

// Health Check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', version: '1.0.1' });
});







app.use((err, req, res, next) => {
    // Mongo's unique index on email — a specific, expected failure, not a crash
    if (err.code === 11000) {
        return res.status(409).json({ message: 'Email already in use' });
    }

    // express.json() flags malformed JSON bodies with a 400 status already attached
    if (err.status === 400 || err.statusCode === 400) {
        return res.status(400).json({ message: 'Invalid request body' });
    }

    // Anything else is genuinely unexpected: log the real error for ourselves,
    // but the client only ever sees a generic message — never a stack trace
    console.error(err);
    res.status(500).json({ message: 'Something went wrong' });
});


export default app;
