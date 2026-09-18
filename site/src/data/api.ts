/**
 * Talks to the local WebScanX engine (python -m webscanx.server).
 *
 * Everything here is loopback-only: if the server isn't running the UI falls
 * back to the bundled sample findings so the design still demos offline.
 */

import { useEffect, useState } from "react";

import { FINDINGS, type Finding, type Severity } from "./findings";

export const API_BASE =
  (import.meta as any).env?.VITE_WEBSCANX_API ?? "http://127.0.0.1:8765";

export type ScanState = "running" | "done" | "error";

export type ScanJob = {
  id: string;
  state: ScanState;
  target: string;
  kind: string;
  started: string;
  finished: string | null;
  toolVersion: string;
  progress: {
    done: number;
    total: number;
    current: string | null;
    scanners: string[];
  };
  counts: Record<string, number>;
  summary: string;
  error: string | null;
  findings?: Finding[];
};

export type StartScanRequest = {
  target: string;
  kind?: "web" | "code";
  authorized?: boolean;
  aggressive?: boolean;
  only?: string[];
  exclude?: string[];
  maxPages?: number;
  depth?: number;
  timeout?: number;
  delay?: number;
};

/** The engine refused the request (bad target, missing authorization, ...). */
export class ApiError extends Error {}

/** The engine isn't reachable at all — offline, not running, wrong port. */
export class OfflineError extends Error {
  constructor() {
    super(
      "Can't reach the local engine. Start it with:  python -m webscanx.server"
    );
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(API_BASE + path, init);
  } catch {
    throw new OfflineError();
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError((body as any).error ?? `HTTP ${res.status}`);
  return body as T;
}

export async function isEngineUp(): Promise<boolean> {
  try {
    await call<{ ok: boolean }>("/api/health");
    return true;
  } catch {
    return false;
  }
}

export function startScan(req: StartScanRequest): Promise<ScanJob> {
  return call<ScanJob>("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
}

export function getScan(id: string): Promise<ScanJob> {
  return call<ScanJob>(`/api/scan/${id}`);
}

export async function listScans(): Promise<ScanJob[]> {
  const { scans } = await call<{ scans: ScanJob[] }>("/api/scans");
  return scans;
}

export function reportUrl(id: string, format: string): string {
  return `${API_BASE}/api/scan/${id}/report?format=${encodeURIComponent(format)}`;
}

/* --------------------------------------------------------- current scan */
/* One tiny store so New Scan -> Scanning -> Results share a job without
   pulling in a state library. The id survives a page refresh. */

const KEY = "webscanx.currentScanId";
let current: ScanJob | null = null;
const listeners = new Set<(job: ScanJob | null) => void>();

export function currentScan(): ScanJob | null {
  return current;
}

export function setCurrentScan(job: ScanJob | null): void {
  current = job;
  try {
    if (job) sessionStorage.setItem(KEY, job.id);
    else sessionStorage.removeItem(KEY);
  } catch {
    /* private mode / storage disabled — the store still works in-memory */
  }
  listeners.forEach((fn) => fn(job));
}

export function subscribeScan(fn: (job: ScanJob | null) => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** Re-attach to the scan this tab was watching (after a refresh). */
export async function restoreCurrentScan(): Promise<ScanJob | null> {
  if (current) return current;
  let id: string | null = null;
  try {
    id = sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
  if (!id) return null;
  try {
    const job = await getScan(id);
    setCurrentScan(job);
    return job;
  } catch {
    setCurrentScan(null);
    return null;
  }
}

/** Poll until the scan finishes, pushing every update into the store. */
export function watchScan(
  id: string,
  { intervalMs = 700 }: { intervalMs?: number } = {}
): () => void {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout>;

  const tick = async () => {
    if (stopped) return;
    try {
      const job = await getScan(id);
      if (stopped) return;
      setCurrentScan(job);
      if (job.state === "running") timer = setTimeout(tick, intervalMs);
    } catch (err) {
      if (stopped) return;
      setCurrentScan({
        ...(current ?? ({} as ScanJob)),
        id,
        state: "error",
        error: err instanceof Error ? err.message : String(err),
      } as ScanJob);
    }
  };

  tick();
  return () => {
    stopped = true;
    clearTimeout(timer);
  };
}

/** React binding for the store above. */
export function useCurrentScan(): ScanJob | null {
  const [job, setJob] = useState<ScanJob | null>(currentScan);
  useEffect(() => {
    setJob(currentScan());
    return subscribeScan(setJob);
  }, []);
  return job;
}

/* ------------------------------------------------------------- helpers */

/** Live findings when a scan has run, the bundled sample otherwise. */
export function findingsOf(job: ScanJob | null): Finding[] {
  return job?.findings?.length ? job.findings : FINDINGS;
}

/** True when what's on screen is the bundled demo, not a real scan. */
export function isSampleData(job: ScanJob | null): boolean {
  return !job?.findings?.length;
}

export function countsOf(job: ScanJob | null): Record<Severity, number> {
  const out = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } as Record<
    Severity,
    number
  >;
  for (const f of findingsOf(job)) out[f.severity] += 1;
  return out;
}
