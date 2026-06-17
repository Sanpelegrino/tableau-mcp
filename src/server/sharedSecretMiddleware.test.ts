import { Request, Response } from 'express';

import { sharedSecretMiddleware, X_MCP_AUTH_HEADER } from './sharedSecretMiddleware.js';

function makeReq(headerValue?: string): Request {
  const headers: Record<string, string> = {};
  if (headerValue !== undefined) {
    headers[X_MCP_AUTH_HEADER] = headerValue;
  }
  return {
    header: (name: string) => headers[name.toLowerCase()],
  } as unknown as Request;
}

function makeRes(): {
  res: Response;
  status: ReturnType<typeof vi.fn>;
  json: ReturnType<typeof vi.fn>;
} {
  const json = vi.fn();
  const status = vi.fn().mockReturnValue({ json });
  const res = { status } as unknown as Response;
  return { res, status, json };
}

describe('sharedSecretMiddleware', () => {
  const ORIG_ENV = { ...process.env };

  beforeEach(() => {
    delete process.env.MCP_SHARED_SECRET;
    delete process.env.MCP_AUTH_DISABLED;
  });

  afterEach(() => {
    process.env = { ...ORIG_ENV };
  });

  it('throws if MCP_SHARED_SECRET unset and not disabled', () => {
    expect(() => sharedSecretMiddleware()).toThrow(/MCP_SHARED_SECRET is required/);
  });

  it('bypasses gate when MCP_AUTH_DISABLED=true', () => {
    process.env.MCP_AUTH_DISABLED = 'true';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status } = makeRes();
    mw(makeReq(), res, next);
    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
  });

  it('rejects with 401 when header is missing', () => {
    process.env.MCP_SHARED_SECRET = 'super-secret';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status, json } = makeRes();
    mw(makeReq(), res, next);
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({ error: 'unauthorized' });
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects with 401 when header value mismatches', () => {
    process.env.MCP_SHARED_SECRET = 'super-secret';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status } = makeRes();
    mw(makeReq('wrong'), res, next);
    expect(status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects with 401 when header value matches prefix only (length differs)', () => {
    process.env.MCP_SHARED_SECRET = 'super-secret';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status } = makeRes();
    mw(makeReq('super-secret-extra'), res, next);
    expect(status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('calls next when header matches secret exactly', () => {
    process.env.MCP_SHARED_SECRET = 'super-secret';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status } = makeRes();
    mw(makeReq('super-secret'), res, next);
    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
  });
});
