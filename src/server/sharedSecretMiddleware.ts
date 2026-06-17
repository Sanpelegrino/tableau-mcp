import crypto from 'crypto';
import { NextFunction, Request, RequestHandler, Response } from 'express';

import { log } from '../logging/logger.js';

export const X_MCP_AUTH_HEADER = 'x-mcp-auth';

export function sharedSecretMiddleware(): RequestHandler {
  const secret = process.env.MCP_SHARED_SECRET;
  const disabled = process.env.MCP_AUTH_DISABLED === 'true';

  if (disabled) {
    log({
      message:
        'MCP_AUTH_DISABLED=true — shared-secret gate is BYPASSED. Unset MCP_AUTH_DISABLED to re-enable.',
      level: 'warning',
      logger: 'server',
    });
    return (_req: Request, _res: Response, next: NextFunction) => next();
  }

  if (!secret) {
    log({
      message:
        'MCP_SHARED_SECRET is not set — refusing to start gated middleware. Set MCP_SHARED_SECRET or MCP_AUTH_DISABLED=true to bypass.',
      level: 'error',
      logger: 'server',
    });
    throw new Error('MCP_SHARED_SECRET is required when MCP_AUTH_DISABLED is not "true"');
  }

  const expected = Buffer.from(secret, 'utf8');

  return (req: Request, res: Response, next: NextFunction) => {
    const headerValue = req.header(X_MCP_AUTH_HEADER);
    if (!headerValue) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }

    const provided = Buffer.from(headerValue, 'utf8');
    if (provided.length !== expected.length) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }

    if (!crypto.timingSafeEqual(provided, expected)) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }

    next();
  };
}
