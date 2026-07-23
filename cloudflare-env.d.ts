interface Fetcher {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

interface D1ResultMeta {
  changes?: number;
  [key: string]: unknown;
}

interface D1Result<T = unknown> {
  error?: string;
  meta: D1ResultMeta;
  results: T[];
  success: boolean;
}

interface D1PreparedStatement {
  all<T = Record<string, unknown>>(): Promise<D1Result<T>>;
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = Record<string, unknown>>(columnName?: string): Promise<T | null>;
  raw<T extends unknown[] = unknown[]>(): Promise<T[]>;
  run<T = Record<string, unknown>>(): Promise<D1Result<T>>;
}

interface D1Database {
  batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>;
  dump(): Promise<ArrayBuffer>;
  exec(query: string): Promise<unknown>;
  prepare(query: string): D1PreparedStatement;
}

declare module "cloudflare:workers" {
  export const env: {
    DB?: D1Database;
    [key: string]: unknown;
  };
}
