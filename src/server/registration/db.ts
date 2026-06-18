import { Pool, PoolConfig, QueryResult, QueryResultRow } from 'pg';

let _pool: Pool | null = null;

function buildPool(): Pool {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL is not set');
  }

  const config: PoolConfig = {
    connectionString,
    ssl: { rejectUnauthorized: false },
  };

  return new Pool(config);
}

export function getPool(): Pool {
  if (_pool === null) {
    _pool = buildPool();
  }
  return _pool;
}

export const pool = new Proxy({} as Pool, {
  get(_target, prop, receiver) {
    const real = getPool();
    const value = Reflect.get(real, prop, receiver);
    return typeof value === 'function' ? value.bind(real) : value;
  },
});

export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params?: ReadonlyArray<unknown>,
): Promise<QueryResult<T>> {
  return getPool().query<T>(text, params as unknown[] | undefined);
}

export async function closePool(): Promise<void> {
  if (_pool !== null) {
    const p = _pool;
    _pool = null;
    await p.end();
  }
}

/**
 * Test-only: replace the underlying pool. Returns a restore function.
 */
export function __setPoolForTests(p: Pool | null): () => void {
  const prev = _pool;
  _pool = p;
  return () => {
    _pool = prev;
  };
}
