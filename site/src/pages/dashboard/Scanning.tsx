import { useEffect, useState } from "react";
import { SEV_COLORS, type Severity } from "@/data/findings";
import {
  countsOf,
  findingsOf,
  isSampleData,
  restoreCurrentScan,
  useCurrentScan,
  watchScan,
} from "@/data/api";

// Shown only when nothing has been scanned yet (design preview, no engine).
const SAMPLE_SCANNERS = [
  "web.headers", "web.tls", "web.xss", "web.sqli", "web.csrf",
];

function moduleLabel(scanner: string): string {
  return scanner.split(".").slice(1).join(".") || scanner;
}

function elapsed(fromIso: string | undefined, now: number): string {
  if (!fromIso) return "--:--";
  const secs = Math.max(0, Math.floor((now - Date.parse(fromIso)) / 1000));
  const mm = String(Math.floor(secs / 60)).padStart(2, "0");
  const ss = String(secs % 60).padStart(2, "0");
  return `${mm}:${ss}`;
}

export default function Scanning() {
  const [logOpen, setLogOpen] = useState(false);
  const job = useCurrentScan();
  const [now, setNow] = useState(() => Date.now());

  // Re-attach after a refresh, then poll until the scan finishes.
  useEffect(() => {
    let stop: (() => void) | undefined;
    restoreCurrentScan().then((restored) => {
      const id = restored?.id;
      if (id) stop = watchScan(id);
    });
    return () => stop?.();
  }, []);

  // Tick the elapsed clock while the scan is running.
  const running = job?.state === "running";
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [running]);

  const findings = findingsOf(job);
  const counts = countsOf(job);
  const sample = isSampleData(job);
  const scanners = job?.progress?.scanners?.length
    ? job.progress.scanners
    : SAMPLE_SCANNERS;
  const done = job?.progress?.done ?? 2;
  const total = job?.progress?.total ?? scanners.length;
  const pct = total ? Math.round((done / total) * 100) : 0;
  const current = job?.progress?.current ?? (sample ? "web.xss" : null);
  const finished = job ? job.state !== "running" : false;

  const feed = [...findings].slice(0, 5);

  return (
    <div className="flex-1 overflow-y-auto px-8 py-8 max-w-[760px]">

      {/* Top bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-8">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 min-w-0">
          <div className="flex items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full ${finished ? "" : "live-pulse"}`}
              style={{ backgroundColor: job?.state === "error" ? "#ef4444" : "#22d3a6" }}
            />
            <span
              className="mono text-[11px] font-semibold tracking-[0.08em]"
              style={{ color: job?.state === "error" ? "#ef4444" : "#22d3a6" }}
            >
              {job?.state === "error" ? "FAILED" : finished ? "COMPLETE" : "SCANNING"}
            </span>
          </div>
          <span className="text-[14px] font-medium text-[#f0eeed] truncate max-w-full">
            {job?.target ?? "https://staging.example.com"}
          </span>
          <span className="mono text-[10px] px-2 py-0.5 border border-[#1e1c1c] text-[#535050] tracking-[0.06em]">
            {(job?.kind ?? "web").toUpperCase()}
          </span>
        </div>
        <div className="flex items-center gap-4">
          <span className="mono text-[11px] text-[#3a3836]">
            ELAPSED{" "}
            <span className="text-[#535050]">
              {job
                ? elapsed(job.started, finished && job.finished ? Date.parse(job.finished) : now)
                : "04:12"}
            </span>
          </span>
          <button
            onClick={() => { window.location.hash = "/dashboard/new-scan"; }}
            className="mono text-[11px] border border-[#1e1c1c] px-3 py-1.5 text-[#535050] hover:text-[#f0eeed] hover:border-[#2a2828] transition-colors duration-150"
          >
            {finished ? "New scan" : "Stop"}
          </button>
        </div>
      </div>

      {job?.state === "error" && (
        <div className="mb-6 border border-[#ef4444]/40 bg-[#ef4444]/5 px-4 py-3 mono text-[11px] text-[#ef4444]">
          {job.error}
        </div>
      )}

      {/* Progress */}
      <div className="mb-8 space-y-3">
        <div className="flex items-center justify-between mono text-[11px] mb-2">
          <div className="flex items-center gap-2 text-[#8a8785]">
            <span className="w-1.5 h-1.5 bg-[#22d3a6]" />
            {current ? `${moduleLabel(current)} — running` : `${done} / ${total} modules`}
          </div>
          <span className="text-[#22d3a6] font-semibold">{pct}%</span>
        </div>
        <div className="w-full h-[2px] bg-[#1e1c1c] overflow-hidden">
          <div className="h-full bg-[#22d3a6] transition-all" style={{ width: `${pct}%` }} />
        </div>

        {/* Module states */}
        <div className="flex flex-wrap gap-2 pt-1">
          {scanners.map((name, i) => {
            const state = i < done ? "done" : name === current ? "running" : "queued";
            return (
              <span
                key={name}
                className={`
                  mono text-[10px] px-2.5 py-1 border flex items-center gap-1.5 tracking-[0.04em]
                  ${state === "done"
                    ? "border-[#1e1c1c] text-[#3a3836]"
                    : state === "running"
                    ? "border-[#22d3a6]/30 bg-[#22d3a6]/5 text-[#22d3a6]"
                    : "border-[#1e1c1c] text-[#2a2828]"
                  }
                `}
              >
                {state === "done" && <span className="text-[#22d3a6]">✓</span>}
                {state === "running" && <span className="w-1.5 h-1.5 bg-[#22d3a6] live-pulse inline-block" />}
                {state === "queued" && <span className="text-[#2a2828]">○</span>}
                {moduleLabel(name)}
              </span>
            );
          })}
        </div>
      </div>

      {/* Live counters */}
      <div className="grid grid-cols-4 gap-3 mb-8">
        {(["HIGH", "MEDIUM", "LOW", "INFO"] as const).map((label) => {
          const count = counts[label as Severity];
          const color = SEV_COLORS[label].bar;
          return (
            <div key={label} className="border border-[#1e1c1c] bg-[#111010] px-4 py-3">
              <div
                className="mono text-[32px] font-semibold leading-none mb-1"
                style={{ color: count > 0 ? color : "#2a2828" }}
              >
                {count}
              </div>
              <div className="mono text-[10px] tracking-[0.07em]" style={{ color: count > 0 ? color + "99" : "#2a2828" }}>
                {label}
              </div>
            </div>
          );
        })}
      </div>

      {/* Live feed */}
      <div className="border border-[#1e1c1c] mb-4">
        <div className="px-4 py-2.5 border-b border-[#1e1c1c] flex items-center justify-between">
          <span className="label-caps text-[#3a3836]">Live findings</span>
          <span className="mono text-[10px] text-[#3a3836] flex items-center gap-1.5">
            {!finished && <span className="w-1 h-1 bg-[#22d3a6] rounded-full live-pulse" />}
            {sample ? "sample data" : finished ? "complete" : "streaming"}
          </span>
        </div>
        <div className="divide-y divide-[#1e1c1c]">
          {feed.length === 0 && (
            <div className="px-4 py-6 mono text-[11px] text-[#3a3836]">
              Nothing found yet.
            </div>
          )}
          {feed.map((f, i) => (
            <div
              key={f.id}
              style={{ borderLeftColor: SEV_COLORS[f.severity].bar }}
              className={`
                flex items-center gap-3 px-4 py-3 border-l-2 transition-colors duration-150
                ${i === 0 ? "bg-[#111010]" : ""}
              `}
            >
              <span
                className="shrink-0 mono text-[10px] font-semibold tracking-[0.05em] px-1.5 py-0.5"
                style={{ color: SEV_COLORS[f.severity].text, backgroundColor: SEV_COLORS[f.severity].bg }}
              >
                {f.severity}
              </span>
              <span className="flex-1 text-[12px] text-[#f0eeed] truncate">{f.name}</span>
              <span className="shrink-0 mono text-[10px] text-[#3a3836] hidden sm:block">{f.path.split(" ")[0]}</span>
              <span className={`shrink-0 mono text-[10px] ${i === 0 ? "text-[#22d3a6]" : "text-[#2a2828]"}`}>{f.module}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Log */}
      <details open={logOpen} onToggle={(e) => setLogOpen((e.target as HTMLDetailsElement).open)} className="border border-[#1e1c1c]">
        <summary className="px-4 py-2.5 cursor-pointer list-none mono text-[11px] text-[#3a3836] hover:text-[#535050] transition-colors duration-150 flex items-center justify-between">
          <span>Engine log</span>
          <span className="text-[#2a2828]">{logOpen ? "▲" : "▼"}</span>
        </summary>
        <div className="border-t border-[#1e1c1c] bg-[#0b0a0a] p-4 max-h-[180px] overflow-y-auto space-y-1.5">
          {scanners.slice(0, done).map((name) => (
            <div key={name} className="flex items-start gap-3 mono text-[10px]">
              <span className="text-[#2a2828] shrink-0">[done]</span>
              <span className="text-[#3a3836]">{name} finished</span>
            </div>
          ))}
          {current && (
            <div className="flex items-start gap-3 mono text-[10px]">
              <span className="text-[#2a2828] shrink-0">[run ]</span>
              <span className="text-[#22d3a6]">{current} running…</span>
            </div>
          )}
          {finished && (
            <div className="flex items-start gap-3 mono text-[10px]">
              <span className="text-[#2a2828] shrink-0">[end ]</span>
              <span className="text-[#3a3836]">{job?.summary}</span>
            </div>
          )}
        </div>
      </details>

      {/* View results */}
      <div className="mt-8 flex items-center gap-4">
        <button
          onClick={() => { window.location.hash = "/dashboard/results"; }}
          className="bg-[#22d3a6] text-[#0b0a0a] font-semibold text-[13px] px-6 py-3 hover:bg-[#1ec49a] transition-colors duration-150"
        >
          View full report →
        </button>
        <span className="mono text-[11px] text-[#3a3836]">
          {findings.length} findings{finished ? "" : " so far — scan continues"}
        </span>
      </div>
    </div>
  );
}
