/* Shapes of the two published documents.
 *
 * Every field is optional and most are `unknown`, deliberately. These files are
 * fetched from a CDN, so the type system must not be allowed to imply a
 * guarantee the network cannot make: the guards in guards.ts are what actually
 * narrows a value, and a confident interface here would only encourage skipping
 * them. */

export interface CategoryFiles {
  [kind: string]: unknown;
}

export interface Category {
  unique?: unknown;
  broken?: unknown;
  duplicates?: unknown;
  total_fetched?: unknown;
  active_sources?: unknown;
  protocols?: Record<string, unknown>;
  files?: CategoryFiles;
}

export interface IndexDoc {
  brand?: unknown;
  generator?: unknown;
  updated_at?: unknown;
  next_update_eta?: unknown;
  update_interval_minutes?: unknown;
  elapsed_seconds?: unknown;
  publish_branch?: unknown;
  link_policy?: Record<string, unknown>;
  categories?: Record<string, Category>;
  protocols?: Record<string, unknown>;
  protocol_files?: Record<string, unknown>;
  protocol_files_base64?: Record<string, unknown>;
  protocol_files_mirror?: Record<string, unknown>;
  archive?: Record<string, unknown>;
  sources?: Record<string, unknown>;
}

export interface SourceRow {
  url?: unknown;
  tier?: unknown;
  name?: unknown;
  status?: unknown;
  count?: unknown;
  http_code?: unknown;
  latency_ms?: unknown;
  attempts?: unknown;
  error?: unknown;
}

export interface ConverterStat {
  total?: unknown;
  by_reason?: Record<string, unknown>;
  by_protocol?: Record<string, unknown>;
}

export interface HealthDoc {
  brand?: unknown;
  checked_at?: unknown;
  elapsed_seconds?: unknown;
  summary?: Record<string, unknown>;
  sources?: unknown;
  converters?: Record<string, ConverterStat>;
  converters_by_category?: Record<string, Record<string, ConverterStat>>;
  brand_gate?: Record<string, Record<string, unknown>>;
  geo?: Record<string, unknown>;
  cascade?: {
    exit_country?: Record<string, unknown>;
    layers?: Record<string, Record<string, unknown>>;
    buckets?: Record<string, unknown>;
    total_seconds?: unknown;
  };
}
