import { Request, Response } from 'express';

import { sharedSecretMiddleware, X_MCP_AUTH_HEADER } from './sharedSecretMiddleware.js';

function makeReq(headers: Record<string, string> = {}): Request {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  return {
    method: 'POST',
    path: '/tableau-mcp',
    headers: lower,
    body: undefined,
    header: (name: string) => lower[name.toLowerCase()],
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

describe('sharedSecretMiddleware (two-path)', () => {
  const ORIG_ENV = { ...process.env };

  beforeEach(() => {
    delete process.env.MCP_SHARED_SECRET;
    delete process.env.MCP_AUTH_DISABLED;
    delete process.env.MCP_AUTH_SNIFF;
    delete process.env.SLACK_JWKS_URL;
    delete process.env.SLACK_EXPECTED_ISS;
    delete process.env.SLACK_EXPECTED_AUD;
    delete process.env.SLACK_ALLOWED_TEAM_IDS;
  });

  afterEach(() => {
    process.env = { ...ORIG_ENV };
  });

  it('throws if no path configured and not disabled and not sniffing', () => {
    expect(() => sharedSecretMiddleware()).toThrow(/No MCP auth path configured/);
  });

  it('bypasses everything when MCP_AUTH_DISABLED=true', async () => {
    process.env.MCP_AUTH_DISABLED = 'true';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status } = makeRes();
    await mw(makeReq(), res, next);
    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
  });

  it('Path A: rejects 401 when shared-secret header missing and Path B unconfigured', async () => {
    process.env.MCP_SHARED_SECRET = 'super-secret';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await mw(makeReq(), res, next);
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({ error: 'unauthorized' });
    expect(next).not.toHaveBeenCalled();
  });

  it('Path A: rejects 401 on mismatched secret', async () => {
    process.env.MCP_SHARED_SECRET = 'super-secret';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status } = makeRes();
    await mw(makeReq({ [X_MCP_AUTH_HEADER]: 'wrong' }), res, next);
    expect(status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('Path A: rejects 401 when secret is a length-different prefix', async () => {
    process.env.MCP_SHARED_SECRET = 'super-secret';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status } = makeRes();
    await mw(makeReq({ [X_MCP_AUTH_HEADER]: 'super-secret-extra' }), res, next);
    expect(status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('Path A: passes on exact match', async () => {
    process.env.MCP_SHARED_SECRET = 'super-secret';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status } = makeRes();
    await mw(makeReq({ [X_MCP_AUTH_HEADER]: 'super-secret' }), res, next);
    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
  });

  it('Path B unconfigured: bearer token alone is rejected when no shared secret either', async () => {
    process.env.MCP_SHARED_SECRET = 'super-secret';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status } = makeRes();
    await mw(makeReq({ authorization: 'Bearer abc.def.ghi' }), res, next);
    expect(status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('Path A match wins even when Path B bearer is present (no JWT verify needed)', async () => {
    process.env.MCP_SHARED_SECRET = 'super-secret';
    process.env.SLACK_JWKS_URL = 'https://slack.example/jwks';
    process.env.SLACK_EXPECTED_ISS = 'https://slack.com';
    process.env.SLACK_EXPECTED_AUD = 'mcp-server';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status } = makeRes();
    await mw(
      makeReq({ [X_MCP_AUTH_HEADER]: 'super-secret', authorization: 'Bearer junk' }),
      res,
      next,
    );
    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
  });

  it('Sniff mode: passes through on no headers and never 401s', async () => {
    process.env.MCP_AUTH_SNIFF = 'true';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status } = makeRes();
    await mw(makeReq(), res, next);
    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
  });

  it('Sniff mode: passes through with bearer token (does not require valid JWT)', async () => {
    process.env.MCP_AUTH_SNIFF = 'true';
    const mw = sharedSecretMiddleware();
    const next = vi.fn();
    const { res, status } = makeRes();
    await mw(makeReq({ authorization: 'Bearer not.a.real.jwt' }), res, next);
    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
  });
});
