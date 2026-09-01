import type { ApiError, JsonObject } from './types';

export type StateTone = 'good' | 'warn' | 'bad' | 'neutral';
export type DriftState = 'drift' | 'in-sync' | 'unknown';

const SENSITIVE_KEY = /pass(word)?|secret|token|credential|private[_ -]?key|api[_ -]?key|authorization|cookie|jwt/i;

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY.test(key);
}

export function safeDisplay(key: string, value: unknown): string {
  if (isSensitiveKey(key)) return '[redacted by policy]';
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
}

export function isUnsupportedError(error?: ApiError): boolean {
  return Boolean(error && (error.status === 501 || error.code === 'unsupported' || /unsupported|capability/i.test(error.message)));
}

export function isOfflineError(error?: ApiError): boolean {
  return Boolean(error && (error.status === 0 || /unreachable|offline|network/i.test(error.message)));
}

export function stateTone(value: unknown): StateTone {
  const text = String(value ?? '').trim().toLowerCase();
  if (/fail|error|offline|unhealthy|degraded/.test(text)) return 'bad';
  if (/warn|pending|unknown|maintenance|draining/.test(text)) return 'warn';
  if (/active|ready|accept|running|healthy|verified|in sync|synced|ok/.test(text)) return 'good';
  return 'neutral';
}

export function driftState(resource: JsonObject): DriftState {
  const value = resource.drift ?? resource.reconciliation;
  if (value === undefined || value === null || value === '') return 'unknown';
  if (typeof value === 'boolean') return value ? 'drift' : 'in-sync';
  const text = String(value).trim().toLowerCase();
  if (['in sync', 'in-sync', 'synced', 'none', 'clear', 'ok'].includes(text)) return 'in-sync';
  if (/drift|diverg|mismatch|out.of.sync|changed/.test(text)) return 'drift';
  return 'unknown';
}
