/**
 * Registration gate middleware.
 *
 * KNOWN LIMITATION — "no HMAC" mode (intentional, accepted tradeoff):
 *
 * The user instruction was to validate that any incoming request comes from an
 * "app" that has been registered with our MCP server, but WITHOUT computing
 * HMACs server-side. The thing we register is the Slack signing secret, and
 * the only request-time artifact derived from that secret is the
 * `X-Slack-Signature` header (an HMAC). If we refuse to compute HMACs, we have
 * no cryptographic way to prove the caller possesses any registered secret.
 *
 * As an explicit tradeoff, this gate performs a REGISTRY-PRESENCE CHECK ONLY:
 *   - if at least one secret has been registered, requests pass;
 *   - if the registry is empty, requests are 401'd with a message pointing the
 *     caller at registration.
 *
 * This means: once anyone registers, the gate effectively opens for everyone.
 * It is NOT per-request authentication. A clear startup warning is emitted so
 * this is not a silent posture. A future change can layer real per-request
 * verification (HMAC of the Slack signing basestring, or a different proof)
 * on top of this gate.
 */

import { NextFunction, Request, RequestHandler, Response } from 'express';

import { log } from '../../logging/logger.js';
import { countRegistered } from './repo.js';

const CACHE_TTL_MS = 30_000;

function summarizeHeadersForSniff(req: Request): Record<string, string> {
  const out: Record<string, string> = {};
  const headers = req.headers as Record<string, string | string[] | undefined>;
  const include = (name: string, raw: string | string[] | undefined): void => {
    if (raw === undefined) return;
    const v = Array.isArray(raw) ? raw.join(',') : raw;
    out[name] = v.length > 512 ? `${v.slice(0, 512)}…` : v;
  };
  const baseline = [
    'user-agent',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'host',
    'origin',
    'referer',
  ];
  for (const name of baseline) include(name, headers[name]);
  for (const [name, value] of Object.entries(headers)) {
    if (name.startsWith('x-slack-') || name.startsWith('x-mcp-')) {
      include(name, value);
    }
  }
  return out;
}

function summarizeBodyForSniff(body: unknown): Record<string, unknown> | undefined {
  if (body === null || typeof body !== 'object') return undefined;
  const obj = body as Record<string, unknown>;
  const summary: Record<string, unknown> = { topKeys: Object.keys(obj) };
  if (typeof obj.jsonrpc === 'string') summary.jsonrpc = obj.jsonrpc;
  if (typeof obj.method === 'string') summary.method = obj.method;
  if (obj.id !== undefined) summary.id = obj.id;
  return summary;
}

type CacheEntry = {
  count: number;
  fetchedAt: number;
};

export type RegistrationGateDeps = {
  countFn?: () => Promise<number>;
  now?: () => number;
};

export function registrationGate(deps: RegistrationGateDeps = {}): RequestHandler {
  const disabled = process.env.MCP_AUTH_DISABLED === 'true';
  const sniff = process.env.MCP_AUTH_SNIFF === 'true';

  if (disabled) {
    log({
      message:
        'MCP_AUTH_DISABLED=true — registration gate is BYPASSED for all requests. Unset MCP_AUTH_DISABLED to re-enable.',
      level: 'warning',
      logger: 'server',
    });
    return (_req, _res, next) => next();
  }

  if (sniff) {
    log({
      message:
        'MCP_AUTH_SNIFF=true — registration gate is OPEN; logging request metadata for analysis. Unset MCP_AUTH_SNIFF before going live.',
      level: 'warning',
      logger: 'server',
    });
    return (req, _res, next) => {
      log({
        message: 'mcp-auth-sniff',
        level: 'info',
        logger: 'server',
        data: {
          method: req.method,
          path: req.path,
          headers: summarizeHeadersForSniff(req),
          body: summarizeBodyForSniff(req.body),
        },
      });
      next();
    };
  }

  log({
    message:
      'Registration gate active in REGISTRY-PRESENCE mode: requests are gated only on whether ANY secret has been registered. No per-request authentication is performed. See registrationGate.ts for the documented "no HMAC" tradeoff.',
    level: 'warning',
    logger: 'server',
  });

  const countFn = deps.countFn ?? countRegistered;
  const now = deps.now ?? (() => Date.now());

  let cache: CacheEntry | null = null;
  let inflight: Promise<number> | null = null;

  async function getCount(): Promise<number> {
    const t = now();
    if (cache && t - cache.fetchedAt < CACHE_TTL_MS) {
      return cache.count;
    }
    if (inflight) {
      return inflight;
    }
    inflight = (async () => {
      try {
        const count = await countFn();
        cache = { count, fetchedAt: now() };
        return count;
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  }

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Only gate JSON-RPC POSTs. The middleware is mounted on the MCP routes,
    // but this is belt-and-suspenders so healthchecks / preflights pass through.
    if (req.method !== 'POST') {
      next();
      return;
    }

    try {
      const count = await getCount();
      if (count > 0) {
        next();
        return;
      }
      const requestId =
        req.body && typeof req.body === 'object' && 'id' in req.body
          ? (req.body as { id?: unknown }).id ?? null
          : null;
      const proto =
        (req.headers['x-forwarded-proto'] as string | undefined)?.split(',')[0]?.trim() ||
        (req.secure ? 'https' : 'http');
      const host =
        (req.headers['x-forwarded-host'] as string | undefined)?.split(',')[0]?.trim() ||
        req.headers.host ||
        'this-mcp-server';
      const registerUrl = `${proto}://${host}/register`;
      const message =
        `Unable to process request — this app is not registered with the MCP server. ` +
        `An administrator must register it at ${registerUrl} before requests will be accepted.`;
      // Return HTTP 200 with a JSON-RPC error envelope. Slack's MCP connector
      // (and most MCP clients) swallow the body on non-2xx HTTP statuses and
      // surface a generic "auth failed" message — wrapping the error in a 200
      // lets the client render `error.message` to the user.
      res.status(200).json({
        jsonrpc: '2.0',
        id: requestId,
        error: {
          code: -32001,
          message,
          data: {
            reason: 'app_not_registered',
            register_url: registerUrl,
          },
        },
      });
    } catch (err) {
      log({
        message: 'registration-gate-db-error',
        level: 'error',
        logger: 'server',
        data: { error: (err as Error).message },
      });
      res.status(503).json({ error: 'service_unavailable' });
    }
  };
}
