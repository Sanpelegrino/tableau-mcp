import crypto from 'crypto';
import { createRemoteJWKSet, jwtVerify, JWTPayload, decodeJwt, decodeProtectedHeader } from 'jose';
import { NextFunction, Request, RequestHandler, Response } from 'express';

import { log } from '../logging/logger.js';

export const X_MCP_AUTH_HEADER = 'x-mcp-auth';

type SlackVerifierConfig = {
  jwks: ReturnType<typeof createRemoteJWKSet>;
  issuer: string;
  audience: string;
  allowedTeamIds: Set<string> | null;
};

function buildSlackVerifier(): SlackVerifierConfig | null {
  const jwksUrl = process.env.SLACK_JWKS_URL;
  const issuer = process.env.SLACK_EXPECTED_ISS;
  const audience = process.env.SLACK_EXPECTED_AUD;
  if (!jwksUrl || !issuer || !audience) {
    log({
      message:
        'Slack JWT verification not configured (SLACK_JWKS_URL / SLACK_EXPECTED_ISS / SLACK_EXPECTED_AUD missing). Path B disabled.',
      level: 'warning',
      logger: 'server',
    });
    return null;
  }

  const allowed = process.env.SLACK_ALLOWED_TEAM_IDS;
  const allowedTeamIds = allowed
    ? new Set(allowed.split(',').map((s) => s.trim()).filter(Boolean))
    : null;

  return {
    jwks: createRemoteJWKSet(new URL(jwksUrl)),
    issuer,
    audience,
    allowedTeamIds,
  };
}

function timingSafeStringEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function summarizeHeaders(req: Request): Record<string, string> {
  const out: Record<string, string> = {};
  const headers = req.headers as Record<string, string | string[] | undefined>;
  const include = (name: string, raw: string | string[] | undefined): void => {
    if (raw === undefined) return;
    const v = Array.isArray(raw) ? raw.join(',') : raw;
    if (name === 'authorization') {
      out[name] = v.toLowerCase().startsWith('bearer ')
        ? `Bearer <jwt:${v.length - 7}b>`
        : `<${v.length}b>`;
    } else if (name === X_MCP_AUTH_HEADER) {
      out[name] = `<${v.length}b>`;
    } else {
      out[name] = v.length > 512 ? `${v.slice(0, 512)}…` : v;
    }
  };

  const baseline = [
    'authorization',
    X_MCP_AUTH_HEADER,
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

function summarizeBody(body: unknown): Record<string, unknown> | undefined {
  if (body === null || typeof body !== 'object') return undefined;
  const obj = body as Record<string, unknown>;
  const summary: Record<string, unknown> = {};
  const top = Object.keys(obj);
  summary.topKeys = top;
  if (typeof obj.jsonrpc === 'string') summary.jsonrpc = obj.jsonrpc;
  if (typeof obj.method === 'string') summary.method = obj.method;
  if (obj.id !== undefined) summary.id = obj.id;

  const params = obj.params;
  if (params !== null && typeof params === 'object') {
    summary.paramsKeys = Object.keys(params as Record<string, unknown>);
  }

  const interestingPattern = /(team|enterprise|workspace|installation|host|url|origin|domain|tenant|slack|user|actor)/i;
  const found: Record<string, unknown> = {};
  const visit = (node: unknown, prefix: string, depth: number): void => {
    if (depth > 6 || node === null || node === undefined) return;
    if (typeof node !== 'object') return;
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      const path = prefix ? `${prefix}.${k}` : k;
      if (interestingPattern.test(k) && (typeof v === 'string' || typeof v === 'number')) {
        const s = String(v);
        found[path] = s.length > 256 ? `${s.slice(0, 256)}…` : s;
      }
      if (typeof v === 'object') visit(v, path, depth + 1);
    }
  };
  visit(obj, '', 0);
  if (Object.keys(found).length > 0) summary.interestingFields = found;
  return summary;
}

function decodeJwtForSniff(token: string): Record<string, unknown> | null {
  try {
    const header = decodeProtectedHeader(token);
    const payload = decodeJwt(token);
    const safe: Record<string, unknown> = {
      header,
      iss: payload.iss,
      aud: payload.aud,
      sub: payload.sub,
      exp: payload.exp,
      iat: payload.iat,
    };
    for (const k of ['team_id', 'enterprise_id', 'user_id', 'scope', 'azp']) {
      if (payload[k] !== undefined) safe[k] = payload[k];
    }
    return safe;
  } catch (err) {
    return { decode_error: (err as Error).message };
  }
}

export function sharedSecretMiddleware(): RequestHandler {
  const sharedSecret = process.env.MCP_SHARED_SECRET;
  const disabled = process.env.MCP_AUTH_DISABLED === 'true';
  const sniff = process.env.MCP_AUTH_SNIFF === 'true';
  const slack = buildSlackVerifier();

  if (disabled) {
    log({
      message:
        'MCP_AUTH_DISABLED=true — auth gate is BYPASSED for all requests. Unset MCP_AUTH_DISABLED to re-enable.',
      level: 'warning',
      logger: 'server',
    });
    return (_req, _res, next) => next();
  }

  if (!sniff && !sharedSecret && !slack) {
    log({
      message:
        'No auth path configured: set MCP_SHARED_SECRET (Path A) or SLACK_JWKS_URL+SLACK_EXPECTED_ISS+SLACK_EXPECTED_AUD (Path B), or MCP_AUTH_DISABLED=true to bypass, or MCP_AUTH_SNIFF=true to observe.',
      level: 'error',
      logger: 'server',
    });
    throw new Error('No MCP auth path configured');
  }

  if (sniff) {
    log({
      message:
        'MCP_AUTH_SNIFF=true — auth gate is OPEN; logging request auth metadata for analysis. Unset MCP_AUTH_SNIFF before going live.',
      level: 'warning',
      logger: 'server',
    });
  }

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const sharedSecretHeader = req.header(X_MCP_AUTH_HEADER);
    const authHeader = req.header('authorization');
    const bearer =
      authHeader && authHeader.toLowerCase().startsWith('bearer ')
        ? authHeader.slice(7).trim()
        : undefined;

    let pathAResult: 'match' | 'mismatch' | 'absent' = 'absent';
    if (sharedSecretHeader !== undefined) {
      pathAResult =
        sharedSecret && timingSafeStringEqual(sharedSecretHeader, sharedSecret)
          ? 'match'
          : 'mismatch';
    }

    let pathBResult: 'match' | 'mismatch' | 'absent' = 'absent';
    let pathBPayload: JWTPayload | undefined;
    let pathBError: string | undefined;
    if (bearer !== undefined) {
      if (!slack) {
        pathBResult = 'mismatch';
        pathBError = 'slack-verifier-not-configured';
      } else {
        try {
          const { payload } = await jwtVerify(bearer, slack.jwks, {
            issuer: slack.issuer,
            audience: slack.audience,
          });
          pathBPayload = payload;
          const teamId =
            (payload as Record<string, unknown>).team_id ??
            (payload as Record<string, unknown>).https_slack_com_team_id;
          if (slack.allowedTeamIds && !slack.allowedTeamIds.has(String(teamId ?? ''))) {
            pathBResult = 'mismatch';
            pathBError = `team-not-allowed:${String(teamId)}`;
          } else {
            pathBResult = 'match';
          }
        } catch (err) {
          pathBResult = 'mismatch';
          pathBError = (err as Error).message;
        }
      }
    }

    if (sniff) {
      log({
        message: 'mcp-auth-sniff',
        level: 'info',
        logger: 'server',
        data: {
          method: req.method,
          path: req.path,
          headers: summarizeHeaders(req),
          body: summarizeBody(req.body),
          pathA: pathAResult,
          pathB: pathBResult,
          pathBError,
          jwt: bearer ? decodeJwtForSniff(bearer) : undefined,
          jwtVerifiedClaims:
            pathBPayload !== undefined
              ? {
                  iss: pathBPayload.iss,
                  aud: pathBPayload.aud,
                  sub: pathBPayload.sub,
                  exp: pathBPayload.exp,
                  team_id: (pathBPayload as Record<string, unknown>).team_id,
                }
              : undefined,
        },
      });
      next();
      return;
    }

    if (pathAResult === 'match' || pathBResult === 'match') {
      next();
      return;
    }

    res.status(401).json({ error: 'unauthorized' });
  };
}
