import { useEffect, useState } from "react";
import { SEV_COLORS } from "@/data/findings";
import { getScan, listScans, setCurrentScan, type ScanJob } from "@/data/api";
import ExportModal from "./ExportModal";

type ScanRow = {
  id: string;
  date: string;
  target: string;
  depth: string;
  duration: string;
  high: number;
  medium: number;
  low: number;
};

function duration(job: ScanJob): string {
  if (!job.finished) return "—";
  const secs = Math.max(0, Math.round((Date.parse(job.finished) - Date.parse(job.started)) / 1000));
  return `${Math.floor(secs / 60)}m ${String(secs % 60).padStart(2, "0")}s`;
}

function toRow(job: ScanJob): ScanRow {
  return {
    id: job.id,
    date: job.started.slice(0, 10),
    target: job.target,
    depth: `${job.progress.total} mods`,
    duration: duration(job),
    high: (job.counts.High ?? 0) + (job.counts.Critical ?? 0),
    medium: job.counts.Medium ?? 0,
    low: job.counts.Low ?? 0,
  };
}

// Shown only when the engine isn't running (design preview).
const ROWS: ScanRow[] = [
  { id: "1", date: "2026-09-15", target: "http://127.0.0.1:63725/",        depth: "Standard", duration: "0m 0s",   high: 3, medium: 2, low: 3 },
  { id: "2", date: "2026-09-14", target: "https://staging.example.com",    depth: "Standard", duration: "3m 42s",  high: 2, medium: 3, low: 5 },
  { id: "3", date: "2026-09-12", target: "https://demo.webscanx.internal", depth: "Deep",     duration: "41m 08s", high: 1, medium: 4, low: 7 },
  { id: "4", date: "2026-09-10", target: "https://dev.internal.corp",      depth: "Quick",    duration: "1m 55s",  high: 0, medium: 1, low: 2 },
  { id: "5", date: "2026-09-07", target: "http://localhost:3000",           depth: "Standard", duration: "9m 14s",  high: 4, medium: 2, low: 1 },
  { id: "6", date: "2026-09-03", target: "https://staging.example.com",    depth: "Standard", duration: "4m 01s",  high: 2, medium: 3, low: 6 },
  { id: "7", date: "2026-08-28", target: "https://demo.webscanx.internal", depth: "Quick",    duration: "2m 12s",  high: 0, medium: 2, low: 3 },
  { id: "8", date: "2026-08-20", target: "http://127.0.0.1:8080",          depth: "Deep",     duration: "47m 33s", high: 5, medium: 1, low: 4 },
];

function MiniBar({ high, medium, low }: { high: number; medium: number; low: number }) {
  const total = high + medium + low;
  if (total === 0) {
    return <span className="mono text-[11px] text-[#2a2828]">—</span>;
  }
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-[3px] w-14 overflow-hidden gap-px">
        {high > 0 && <div className="h-full" style={{ width: `${(high / total) * 100}%`, backgroundColor: SEV_COLORS.HIGH.bar }} />}
        {medium > 0 && <div className="h-full" style={{ width: `${(medium / total) * 100}%`, backgroundColor: SEV_COLORS.MEDIUM.bar }} />}
        {low > 0 && <div className="h-full" style={{ width: `${(low / total) * 100}%`, backgroundColor: SEV_COLORS.LOW.bar }} />}
      </div>
      <span className="mono text-[11px] text-[#535050]">
        {high > 0 && <span style={{ color: SEV_COLORS.HIGH.bar }}>{high}H</span>}
        {high > 0 && (medium > 0 || low > 0) && <span className="text-[#2a2828]"> </span>}
        {medium > 0 && <span style={{ color: SEV_COLORS.MEDIUM.bar }}>{medium}M</span>}
        {medium > 0 && low > 0 && <span className="text-[#2a2828]"> </span>}
        {low > 0 && <span style={{ color: SEV_COLORS.LOW.bar }}>{low}L</span>}
      </span>
    </div>
  );
}

export default function History() {
  const [search, setSearch] = useState("");
  const [showExport, setShowExport] = useState(false);
  const [hovered, setHovered] = useState<string | null>(null);
  const [live, setLive] = useState<ScanJob[] | null>(null);

  useEffect(() => {
    listScans().then(setLive).catch(() => setLive(null));
  }, []);

  const rows = live?.length ? live.map(toRow) : ROWS;
  const sample = !live?.length;

  const filtered = rows.filter((r) =>
    r.target.toLowerCase().includes(search.toLowerCase())
  );

  /** Make `id` the scan every other screen is looking at. */
  async function load(id: string): Promise<boolean> {
    if (sample) return false;
    try {
      setCurrentScan(await getScan(id));
      return true;
    } catch {
      return false;  // the engine went away
    }
  }

  async function open(id: string) {
    await load(id);
    window.location.hash = "/dashboard/results";
  }

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="px-8 py-8">

        {/* Header */}
        <div className="flex flex-wrap items-end justify-between gap-4 mb-6">
          <div>
            <h1 className="text-[22px] font-semibold tracking-[-0.02em] text-[#f0eeed]">History</h1>
            <p className="mono text-[11px] text-[#3a3836] mt-1">
              {sample ? "sample data" : "held by the running engine"}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter targets…"
              className="bg-[#111010] border border-[#1e1c1c] text-[#f0eeed] px-3 py-1.5 mono text-[11px] placeholder-[#2a2828] outline-none focus:border-[#22d3a6] transition-colors duration-150 flex-1 min-w-[140px] sm:flex-none sm:w-[200px]"
            />
            <button className="mono text-[11px] border border-[#1e1c1c] px-3 py-1.5 text-[#3a3836] hover:text-[#535050] hover:border-[#2a2828] transition-colors duration-150 whitespace-nowrap">
              Compare two scans
            </button>
          </div>
        </div>

        {/* Table */}
        <div className="border border-[#1e1c1c] overflow-x-auto">
          <div className="min-w-[560px]">
          {/* Header row */}
          <div className="flex items-center px-5 py-2.5 border-b border-[#1e1c1c] bg-[#111010]">
            <span className="label-caps text-[#2a2828] w-[90px] shrink-0">Date</span>
            <span className="label-caps text-[#2a2828] flex-1">Target</span>
            <span className="label-caps text-[#2a2828] w-[70px] shrink-0 hidden sm:block">Depth</span>
            <span className="label-caps text-[#2a2828] w-[70px] shrink-0 hidden md:block">Duration</span>
            <span className="label-caps text-[#2a2828] w-[150px] shrink-0">Findings</span>
            <span className="label-caps text-[#2a2828] w-[100px] shrink-0 text-right">Actions</span>
          </div>

          {filtered.length === 0 && (
            <p className="px-5 py-6 mono text-[11px] text-[#2a2828]">No scans match.</p>
          )}

          {filtered.map((r) => (
            <div
              key={r.id}
              onMouseEnter={() => setHovered(r.id)}
              onMouseLeave={() => setHovered(null)}
              className={`flex items-center px-5 py-3 border-b border-[#1e1c1c] last:border-b-0 transition-colors duration-150 ${hovered === r.id ? "bg-[#111010]" : ""}`}
            >
              <span className="w-[90px] shrink-0 mono text-[11px] text-[#535050]">{r.date}</span>
              <span className="flex-1 min-w-0 mono text-[12px] text-[#f0eeed] truncate pr-4">{r.target}</span>
              <span className="w-[70px] shrink-0 mono text-[11px] text-[#3a3836] hidden sm:block">{r.depth}</span>
              <span className="w-[70px] shrink-0 mono text-[11px] text-[#3a3836] hidden md:block">{r.duration}</span>
              <div className="w-[150px] shrink-0">
                <MiniBar high={r.high} medium={r.medium} low={r.low} />
              </div>
              <div className="w-[100px] shrink-0 flex items-center justify-end gap-3 mono text-[11px]">
                <button
                  onClick={() => open(r.id)}
                  className="text-[#535050] hover:text-[#22d3a6] transition-colors duration-150"
                >
                  Open
                </button>
                <button
                  onClick={async () => { await load(r.id); setShowExport(true); }}
                  className="text-[#535050] hover:text-[#f0eeed] transition-colors duration-150"
                >
                  Export
                </button>
                <button className="text-[#2a2828] hover:text-[#ef4444] transition-colors duration-150">
                  ✕
                </button>
              </div>
            </div>
          ))}
          </div>
        </div>

        <p className="mono text-[10px] text-[#2a2828] mt-4">
          {sample
            ? `${ROWS.length} scans (sample data — start the engine to see your own)`
            : `${rows.length} scans this engine session`}
        </p>
      </div>

      {showExport && <ExportModal onClose={() => setShowExport(false)} />}
    </div>
  );
}
