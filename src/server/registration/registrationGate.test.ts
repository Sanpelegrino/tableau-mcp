import type { NextFunction, Request, Response } from 'express';

import { registrationGate } from './registrationGate.js';

function makeReq(
  method: string = 'POST',
  headers: Record<string, string> = { host: 'mcp.example.com', 'x-forwarded-proto': 'https' },
): Request {
  return {
    method,
    path: '/tableau-mcp',
    headers,
    body: { jsonrpc: '2.0', method: 'tools/call', id: 1 },
  } as unknown as Request;
}

function makeRes(): {
  res: Response;
  status: ReturnType<typeof vi.fn>;
  json: ReturnType<typeof vi.fn>;
} {
  const json = vi.fn();
  const status = vi.fn().mockReturnValue({ json });
  const res = { status, json } as unknown as Response;
  return { res, status, json };
}

describe('registrationGate', () => {
  const ORIG_ENV = { ...process.env };

  beforeEach(() => {
    delete process.env.MCP_AUTH_DISABLED;
    delete process.env.MCP_AUTH_SNIFF;
  });

  afterEach(() => {
    process.env = { ...ORIG_ENV };
    vi.useRealTimers();
  });

  it('passes through every request when MCP_AUTH_DISABLED=true', async () => {
    process.env.MCP_AUTH_DISABLED = 'true';
    const countFn = vi.fn().mockResolvedValue(0);
    const handler = registrationGate({ countFn });

    const next = vi.fn() as NextFunction;
    const { res, status } = makeRes();

    await handler(makeReq(), res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(status).not.toHaveBeenCalled();
    expect(countFn).not.toHaveBeenCalled();
  });

  it('passes through and never queries the DB when MCP_AUTH_SNIFF=true', async () => {
    process.env.MCP_AUTH_SNIFF = 'true';
    const countFn = vi.fn().mockResolvedValue(0);
    const handler = registrationGate({ countFn });

    const next = vi.fn() as NextFunction;
    const { res, status } = makeRes();

    await handler(makeReq(), res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(status).not.toHaveBeenCalled();
    expect(countFn).not.toHaveBeenCalled();
  });

  it('returns 200 tool-result error for tools/call so MCP clients surface the message', async () => {
    const countFn = vi.fn().mockResolvedValue(0);
    const handler = registrationGate({ countFn });

    const next = vi.fn() as NextFunction;
    const { res, status, json } = makeRes();

    await handler(makeReq(), res, next);

    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(200);
    const payload = json.mock.calls[0][0];
    expect(payload.jsonrpc).toBe('2.0');
    expect(payload.id).toBe(1);
    expect(payload.result.isError).toBe(true);
    expect(payload.result.content[0].type).toBe('text');
    expect(payload.result.content[0].text).toContain('not registered');
    expect(payload.result.content[0].text).toContain('https://mcp.example.com/register');
    expect(payload.error).toBeUndefined();
  });

  it('returns JSON-RPC error envelope for non-tools/call methods', async () => {
    const countFn = vi.fn().mockResolvedValue(0);
    const handler = registrationGate({ countFn });

    const next = vi.fn() as NextFunction;
    const { res, status, json } = makeRes();

    const req = {
      method: 'POST',
      path: '/tableau-mcp',
      headers: { host: 'mcp.example.com', 'x-forwarded-proto': 'https' },
      body: { jsonrpc: '2.0', method: 'initialize', id: 7 },
    } as unknown as Request;

    await handler(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(200);
    const payload = json.mock.calls[0][0];
    expect(payload.error.code).toBe(-32001);
    expect(payload.error.data.register_url).toBe('https://mcp.example.com/register');
  });

  it('calls next() when registry is non-empty', async () => {
    const countFn = vi.fn().mockResolvedValue(3);
    const handler = registrationGate({ countFn });

    const next = vi.fn() as NextFunction;
    const { res, status } = makeRes();

    await handler(makeReq(), res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(status).not.toHaveBeenCalled();
  });

  it('returns 503 when the DB call throws', async () => {
    const countFn = vi.fn().mockRejectedValue(new Error('boom'));
    const handler = registrationGate({ countFn });

    const next = vi.fn() as NextFunction;
    const { res, status, json } = makeRes();

    await handler(makeReq(), res, next);

    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(503);
    expect(json).toHaveBeenCalledWith({ error: 'service_unavailable' });
  });

  it('passes through non-POST requests without consulting the registry', async () => {
    const countFn = vi.fn().mockResolvedValue(0);
    const handler = registrationGate({ countFn });

    const next = vi.fn() as NextFunction;
    const { res, status } = makeRes();

    await handler(makeReq('GET'), res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(status).not.toHaveBeenCalled();
    expect(countFn).not.toHaveBeenCalled();
  });

  it('caches the registry count for 30s and re-queries after expiry', async () => {
    let nowMs = 1_000_000;
    const countFn = vi.fn().mockResolvedValue(1);
    const handler = registrationGate({ countFn, now: () => nowMs });

    const next = vi.fn() as NextFunction;
    const { res } = makeRes();

    await handler(makeReq(), res, next);
    expect(countFn).toHaveBeenCalledTimes(1);

    // 10s later — still cached.
    nowMs += 10_000;
    await handler(makeReq(), res, next);
    expect(countFn).toHaveBeenCalledTimes(1);

    // 29.9s after first fetch — still cached.
    nowMs += 19_900;
    await handler(makeReq(), res, next);
    expect(countFn).toHaveBeenCalledTimes(1);

    // 30.1s after first fetch — cache expired, re-query.
    nowMs += 200;
    await handler(makeReq(), res, next);
    expect(countFn).toHaveBeenCalledTimes(2);

    expect(next).toHaveBeenCalledTimes(4);
  });
});
