import express, { NextFunction, Request, RequestHandler, Response, Router } from 'express';
import session from 'express-session';
import passport from 'passport';
import { Profile, Strategy as GoogleStrategy, VerifyCallback } from 'passport-google-oauth20';

import { deleteById, insertSecret, listByEmail } from './repo.js';

// Note: when running behind Heroku's HTTPS proxy, the host application should
// call `app.set('trust proxy', 1)` before mounting this router so that the
// secure session cookie is correctly issued for HTTPS requests forwarded by
// the load balancer.

interface SessionUser {
  email: string;
  displayName: string;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface User extends SessionUser {}
  }
}

function getAllowedDomain(): string {
  return process.env.GOOGLE_OAUTH_ALLOWED_DOMAIN || 'salesforce.com';
}

export function buildSessionMiddleware(): RequestHandler {
  const secret = process.env.SESSION_SECRET;
  if (!secret) {
    throw new Error('SESSION_SECRET is not set');
  }
  return session({
    secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      sameSite: 'lax',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    },
  });
}

function configurePassport(): void {
  // Idempotent: only register strategy + serializers once across multiple
  // router builds (e.g. test suites).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const anyPassport = passport as any;
  if (anyPassport.__tableauMcpRegistrationConfigured) {
    return;
  }
  anyPassport.__tableauMcpRegistrationConfigured = true;

  passport.serializeUser<SessionUser>((user, done) => {
    done(null, user as SessionUser);
  });
  passport.deserializeUser<SessionUser>((obj, done) => {
    done(null, obj);
  });

  const clientID = process.env.GOOGLE_OAUTH_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_OAUTH_CLIENT_SECRET;
  const callbackURL = process.env.GOOGLE_OAUTH_CALLBACK_URL;

  // We register the strategy lazily — if env vars are missing, skip
  // registration so that non-OAuth routes (and tests) still work.
  if (!clientID || !clientSecret || !callbackURL) {
    return;
  }

  passport.use(
    new GoogleStrategy(
      {
        clientID,
        clientSecret,
        callbackURL,
        scope: ['openid', 'email', 'profile'],
      },
      (
        _accessToken: string,
        _refreshToken: string,
        profile: Profile,
        done: VerifyCallback,
      ) => {
        const email = profile.emails?.[0]?.value;
        if (!email) {
          return done(new Error('Google profile has no email'));
        }
        const allowed = getAllowedDomain();
        const domain = email.split('@')[1] || '';
        if (domain.toLowerCase() !== allowed.toLowerCase()) {
          return done(null, false, { message: `Email domain ${domain} not allowed` });
        }
        const user: SessionUser = {
          email,
          displayName: profile.displayName || email,
        };
        return done(null, user);
      },
    ),
  );
}

function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (req.isAuthenticated && req.isAuthenticated() && req.user) {
    next();
    return;
  }
  res.redirect('/auth/google');
}

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderPage(opts: {
  email: string;
  registrations: Array<{ id: string; created_at: Date; last_used_at: Date | null }>;
  flash?: { type: 'success' | 'error'; message: string };
}): string {
  const { email, registrations, flash } = opts;
  const rows = registrations
    .map((r) => {
      const created = r.created_at instanceof Date ? r.created_at.toISOString() : String(r.created_at);
      const used = r.last_used_at
        ? r.last_used_at instanceof Date
          ? r.last_used_at.toISOString()
          : String(r.last_used_at)
        : 'never';
      return `
        <tr>
          <td><code>${escapeHtml(r.id)}</code></td>
          <td>${escapeHtml(created)}</td>
          <td>${escapeHtml(used)}</td>
          <td>
            <form method="post" action="/register/delete" style="margin:0"
              onsubmit="return confirm('Delete this registration? Once deleted, the corresponding Slack app will be bounced with a 401 until it is re-registered.');">
              <input type="hidden" name="id" value="${escapeHtml(r.id)}" />
              <button type="submit" class="danger">Delete</button>
            </form>
          </td>
        </tr>
      `;
    })
    .join('');

  const flashHtml = flash
    ? `<div class="flash flash-${flash.type}">${escapeHtml(flash.message)}</div>`
    : '';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Tableau MCP — Register Slack Signing Secret</title>
  <style>
    :root { color-scheme: dark; }
    body {
      background: #0b0b0b;
      color: #e6e6e6;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 2rem;
      max-width: 820px;
      margin-left: auto;
      margin-right: auto;
    }
    h1 { font-size: 1.4rem; margin-bottom: 0.25rem; }
    .who { color: #9aa0a6; font-size: 0.9rem; margin-bottom: 2rem; }
    .who form { display: inline; }
    .who button {
      background: transparent;
      color: #9aa0a6;
      border: 1px solid #333;
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.8rem;
    }
    h2 { font-size: 1.05rem; margin-top: 2rem; }
    .instructions {
      background: #141414;
      border: 1px solid #222;
      border-radius: 6px;
      padding: 1rem 1.25rem;
      line-height: 1.55;
    }
    .instructions ol { margin: 0; padding-left: 1.2rem; }
    .instructions img {
      display: block;
      margin-top: 1rem;
      max-width: 100%;
      border: 1px solid #2a2a2a;
      border-radius: 4px;
    }
    label { display: block; margin: 1rem 0 0.4rem; font-weight: 600; }
    textarea {
      width: 100%;
      min-height: 90px;
      background: #050505;
      color: #f5f5f5;
      border: 1px solid #2a2a2a;
      border-radius: 4px;
      padding: 0.6rem;
      font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
      font-size: 0.95rem;
      box-sizing: border-box;
    }
    button.primary {
      background: #4a154b;
      color: #fff;
      border: none;
      padding: 0.6rem 1.2rem;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.95rem;
      margin-top: 0.8rem;
    }
    button.primary:hover { background: #611f64; }
    button.danger {
      background: transparent;
      color: #ff7676;
      border: 1px solid #5a1f1f;
      padding: 0.3rem 0.6rem;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.8rem;
    }
    button.danger:hover { background: #2a0d0d; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 0.5rem;
      font-size: 0.88rem;
    }
    th, td {
      text-align: left;
      padding: 0.5rem 0.6rem;
      border-bottom: 1px solid #1c1c1c;
    }
    th { color: #9aa0a6; font-weight: 500; }
    code { font-family: 'SFMono-Regular', Consolas, Menlo, monospace; color: #c8c8c8; }
    .flash {
      padding: 0.6rem 0.9rem;
      border-radius: 4px;
      margin-bottom: 1rem;
      font-size: 0.9rem;
    }
    .flash-success { background: #0f3a1f; color: #b9f0c7; border: 1px solid #1d6a36; }
    .flash-error { background: #3a0f0f; color: #f0b9b9; border: 1px solid #6a1d1d; }
    .empty { color: #777; font-style: italic; }
  </style>
</head>
<body>
  <h1>Register a Slack Signing Secret</h1>
  <div class="who">
    Signed in as <strong>${escapeHtml(email)}</strong>
    <form method="post" action="/auth/logout">
      <button type="submit">Sign out</button>
    </form>
  </div>

  ${flashHtml}

  <h2>Where do I find my Slack signing secret?</h2>
  <div class="instructions">
    <ol>
      <li>Go to <code>api.slack.com/apps</code> and select your Slack app.</li>
      <li>Click <strong>Basic Information</strong> in the sidebar.</li>
      <li>Scroll to <strong>App Credentials</strong> &rarr; <strong>Signing Secret</strong>.</li>
      <li>Click <strong>Show</strong> and copy the value.</li>
      <li>Paste it below.</li>
    </ol>
    <img src="/register/slack-secret-screenshot.png" alt="Slack signing secret location" />
  </div>

  <form method="post" action="/register">
    <label for="secret">Slack signing secret</label>
    <textarea id="secret" name="secret" autocomplete="off" spellcheck="false" required></textarea>
    <button type="submit" class="primary">Register secret</button>
  </form>

  <h2>Your registered secrets</h2>
  ${
    registrations.length === 0
      ? '<p class="empty">No secrets registered yet.</p>'
      : `<table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Registered</th>
              <th>Last used</th>
              <th></th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>`
  }
</body>
</html>`;
}

export function buildRegistrationRouter(): Router {
  configurePassport();

  const router: Router = express.Router();
  const formParser = express.urlencoded({ extended: false });

  router.use(passport.initialize());
  router.use(passport.session());

  router.get('/auth/google', (req, res, next) => {
    passport.authenticate('google', {
      scope: ['openid', 'email', 'profile'],
    })(req, res, next);
  });

  router.get('/auth/google/callback', (req, res, next) => {
    passport.authenticate('google', {
      failureRedirect: '/register?error=auth',
    })(req, res, () => {
      res.redirect('/register');
    });
  });

  router.post('/auth/logout', (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      if (req.session) {
        req.session.destroy(() => {
          res.redirect('/');
        });
      } else {
        res.redirect('/');
      }
    });
  });

  router.get('/register', requireAuth, async (req, res, next) => {
    try {
      const user = req.user as SessionUser;
      const registrations = await listByEmail(user.email);
      const errParam = typeof req.query.error === 'string' ? req.query.error : undefined;
      const okParam = typeof req.query.ok === 'string' ? req.query.ok : undefined;
      let flash: { type: 'success' | 'error'; message: string } | undefined;
      if (errParam === 'auth') {
        flash = { type: 'error', message: 'Google sign-in failed. Please try again.' };
      } else if (errParam === 'empty') {
        flash = { type: 'error', message: 'Secret cannot be empty.' };
      } else if (okParam === '1') {
        flash = { type: 'success', message: 'Secret registered.' };
      } else if (okParam === 'deleted') {
        flash = { type: 'success', message: 'Secret deleted.' };
      }
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(renderPage({ email: user.email, registrations, flash }));
    } catch (err) {
      next(err);
    }
  });

  router.post('/register', formParser, requireAuth, async (req, res, next) => {
    try {
      const user = req.user as SessionUser;
      const raw = typeof req.body?.secret === 'string' ? req.body.secret : '';
      const secret = raw.trim();
      if (!secret) {
        res.redirect('/register?error=empty');
        return;
      }
      await insertSecret(secret, user.email);
      res.redirect('/register?ok=1');
    } catch (err) {
      next(err);
    }
  });

  router.post('/register/delete', formParser, requireAuth, async (req, res, next) => {
    try {
      const user = req.user as SessionUser;
      const id = typeof req.body?.id === 'string' ? req.body.id.trim() : '';
      if (!id) {
        res.redirect('/register');
        return;
      }
      await deleteById(id, user.email);
      res.redirect('/register?ok=deleted');
    } catch (err) {
      next(err);
    }
  });

  return router;
}
