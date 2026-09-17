import { useState } from "react";
import { FINDINGS, SEV_COLORS } from "@/data/findings";

const MODULES = [
  { id: "headers", label: "Security headers", state: "done" as const },
  { id: "tls", label: "TLS", state: "done" as const },
  { id: "xss", label: "XSS", state: "running" as const },
  { id: "sqli", label: "SQL injection", state: "queued" as const },
  { id: "csrf", label: "CSRF", state: "queued" as const },
];

const LOG: { ts: string; text: string; kind: "normal" | "finding" | "active" }[] = [
  { ts: "00:10", text: "GET http://127.0.0.1:63725/ → 200 (1.2kb)", kind: "normal" },
  { ts: "00:12", text: "FINDING [HIGH] no HTTPS redirect detected", kind: "finding" },
  { ts: "00:27", text: 'DISPATCH xss probe "><wsxTEST> on /?q=', kind: "normal" },
  { ts: "00:28", text: "FINDING [HIGH] marker reflected unescaped in response", kind: "finding" },
  { ts: "00:35", text: "GET /?q=test → 200 (2.1kb) — checking headers...", kind: "normal" },
  { ts: "00:38", text: "GET /login → 200 — checking headers...", kind: "active" },
];

// Findings from done (headers, tls) + running (xss) modules at 62%
// ids: 1=TLS/HIGH, 2=XSS/HIGH, 4=HEADERS/MED, 6=HEADERS/LOW, 7=HEADERS/LOW, 8=HEADERS/LOW
const DONE_FINDING_IDS = new Set([1, 2, 4, 6, 7, 8]);
const COUNTS = { high: 2, medium: 1, low: 3, info: 0 };

export default function Scanning() {
  const [logOpen, setLogOpen] = useState(false);

  const liveFeed = FINDINGS
    .filter((f) => DONE_FINDING_IDS.has(f.id))
    .slice(0, 5)
    .map((f, i) => ({
      ...f,
      time: ["00:28", "00:12", "00:10", "00:08", "00:06"][i],
      isLatest: i === 0,
    }));

  return (
    <div className="flex-1 overflow-y-auto px-8 py-8 max-w-[760px]">

      {/* Top bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-8">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#22d3a6] live-pulse" />
            <span className="mono text-[11px] text-[#22d3a6] font-semibold tracking-[0.08em]">SCANNING</span>
          </div>
          <span className="text-[14px] font-medium text-[#f0eeed]">https://staging.example.com</span>
          <span className="mono text-[10px] px-2 py-0.5 border border-[#1e1c1c] text-[#535050] tracking-[0.06em]">STANDARD</span>
        </div>
        <div className="flex items-center gap-4">
          <span className="mono text-[11px] text-[#3a3836]">
            ELAPSED <span className="text-[#535050]">04:12</span>
          </span>
          <button
            onClick={() => { window.location.hash = "/dashboard/new-scan"; }}
            className="mono text-[11px] border border-[#1e1c1c] px-3 py-1.5 text-[#535050] hover:text-[#f0eeed] hover:border-[#2a2828] transition-colors duration-150"
          >
            Stop
          </button>
        </div>
      </div>

      {/* Progress */}
      <div className="mb-8 space-y-3">
        <div className="flex items-center justify-between mono text-[11px] mb-2">
          <div className="flex items-center gap-2 text-[#8a8785]">
            <span className="w-1.5 h-1.5 bg-[#22d3a6]" />
            XSS — reflected parameters (38 / 61 requests)
          </div>
          <span className="text-[#22d3a6] font-semibold">62%</span>
        </div>
        <div className="w-full h-[2px] bg-[#1e1c1c] overflow-hidden">
          <div className="h-full bg-[#22d3a6] transition-all" style={{ width: "62%" }} />
        </div>

        {/* Module states */}
        <div className="flex flex-wrap gap-2 pt-1">
          {MODULES.map((m) => (
            <span
              key={m.id}
              className={`
                mono text-[10px] px-2.5 py-1 border flex items-center gap-1.5 tracking-[0.04em]
                ${m.state === "done"
                  ? "border-[#1e1c1c] text-[#3a3836]"
                  : m.state === "running"
                  ? "border-[#22d3a6]/30 bg-[#22d3a6]/5 text-[#22d3a6]"
                  : "border-[#1e1c1c] text-[#2a2828]"
                }
              `}
            >
              {m.state === "done" && <span className="text-[#22d3a6]">✓</span>}
              {m.state === "running" && <span className="w-1.5 h-1.5 bg-[#22d3a6] live-pulse inline-block" />}
              {m.state === "queued" && <span className="text-[#2a2828]">○</span>}
              {m.label}
            </span>
          ))}
        </div>
      </div>

      {/* Live counters */}
      <div className="grid grid-cols-4 gap-3 mb-8">
        {(["HIGH", "MEDIUM", "LOW", "INFO"] as const).map((label) => {
          const count = COUNTS[label.toLowerCase() as keyof typeof COUNTS];
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
            <span className="w-1 h-1 bg-[#22d3a6] rounded-full live-pulse" />
            streaming
          </span>
        </div>
        <div className="divide-y divide-[#1e1c1c]">
          {[...liveFeed].reverse().map((f, i) => (
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
              <span className={`shrink-0 mono text-[10px] ${i === 0 ? "text-[#22d3a6]" : "text-[#2a2828]"}`}>{f.time}</span>
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
          {LOG.map((l, i) => (
            <div key={i} className="flex items-start gap-3 mono text-[10px]">
              <span className="text-[#2a2828] shrink-0">[{l.ts}]</span>
              <span className={
                l.kind === "finding" ? "text-[#EF4444]/80" :
                l.kind === "active" ? "text-[#22d3a6]" :
                "text-[#3a3836]"
              }>
                {l.text}
              </span>
            </div>
          ))}
          <div className="flex items-center gap-1.5 mono text-[10px] text-[#22d3a6] pt-0.5">
            <span className="w-1 h-1 bg-[#22d3a6] rounded-full live-pulse" /> live stream active
          </div>
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
        <span className="mono text-[11px] text-[#3a3836]">5 findings so far — scan continues</span>
      </div>
    </div>
  );
}
