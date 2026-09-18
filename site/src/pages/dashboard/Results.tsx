import { useState, type ReactNode } from "react";
import { FINDINGS, SCAN_META, SEV_COLORS, type Severity, type Finding } from "@/data/findings";
import CopyButton from "@/components/CopyButton";
import ExportModal from "./ExportModal";

type Filter = "All" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type DetailTab = "what" | "evidence" | "fix" | "refs";

const FILTER_OPTIONS: { key: Filter; label: string }[] = [
  { key: "All", label: "All" },
  { key: "CRITICAL", label: "Critical" },
  { key: "HIGH", label: "High" },
  { key: "MEDIUM", label: "Medium" },
  { key: "LOW", label: "Low" },
  { key: "INFO", label: "Info" },
];

const DETAIL_TABS: { key: DetailTab; label: string }[] = [
  { key: "what", label: "What" },
  { key: "evidence", label: "Evidence" },
  { key: "fix", label: "Fix" },
  { key: "refs", label: "Refs" },
];

const { counts } = SCAN_META;
const TOTAL = counts.high + counts.medium + counts.low + counts.info;

function SevBadge({ sev }: { sev: Severity }) {
  const s = SEV_COLORS[sev];
  return (
    <span
      className="mono text-[10px] font-semibold tracking-[0.05em] px-1.5 py-0.5"
      style={{ color: s.text, backgroundColor: s.bg }}
    >
      {sev}
    </span>
  );
}

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <p className="label-caps text-[#3a3836] mb-2">{children}</p>
  );
}

export default function Results() {
  const [selectedId, setSelectedId] = useState(FINDINGS[0].id);
  const [filter, setFilter] = useState<Filter>("All");
  const [search, setSearch] = useState("");
  const [showExport, setShowExport] = useState(false);
  const [activeTab, setActiveTab] = useState<DetailTab>("what");

  function select(id: number) {
    setSelectedId(id);
    setActiveTab("what");
  }

  const filtered = FINDINGS.filter((f) => {
    if (filter !== "All" && f.severity !== filter) return false;
    if (search && !f.name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const sel: Finding = FINDINGS.find((f) => f.id === selectedId) ?? FINDINGS[0];

  const filterCount = (k: Filter) =>
    k === "All" ? FINDINGS.length : FINDINGS.filter((f) => f.severity === k).length;

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* ── Header ── */}
      <header className="shrink-0 px-6 py-4 border-b border-[#1e1c1c]">
        <div className="flex items-start justify-between gap-4">
          <div>
            {/* Meta */}
            <div className="flex flex-wrap items-center gap-3 mono text-[11px] mb-3">
              <span className="text-[#535050]">TARGET</span>
              <span className="text-[#f0eeed] font-medium">{SCAN_META.target}</span>
              <span className="text-[#1e1c1c]">·</span>
              <span className="text-[#535050]">{SCAN_META.dateDisplay}</span>
              <span className="text-[#1e1c1c]">·</span>
              <span className="text-[#535050]">{SCAN_META.tool}</span>
            </div>

            {/* Severity bar + counts */}
            <div className="flex items-center gap-4">
              <div className="flex h-[3px] w-36 overflow-hidden gap-px">
                <div style={{ width: `${(counts.high / TOTAL) * 100}%`, backgroundColor: SEV_COLORS.HIGH.bar }} />
                <div style={{ width: `${(counts.medium / TOTAL) * 100}%`, backgroundColor: SEV_COLORS.MEDIUM.bar }} />
                <div style={{ width: `${(counts.low / TOTAL) * 100}%`, backgroundColor: SEV_COLORS.LOW.bar }} />
              </div>
              <div className="flex items-center gap-4 mono text-[11px]">
                <span className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 inline-block" style={{ backgroundColor: SEV_COLORS.HIGH.bar }} />
                  <span className="font-semibold" style={{ color: SEV_COLORS.HIGH.bar }}>{counts.high} High</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 inline-block" style={{ backgroundColor: SEV_COLORS.MEDIUM.bar }} />
                  <span className="font-semibold" style={{ color: SEV_COLORS.MEDIUM.bar }}>{counts.medium} Medium</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 inline-block" style={{ backgroundColor: SEV_COLORS.LOW.bar }} />
                  <span className="font-semibold" style={{ color: SEV_COLORS.LOW.bar }}>{counts.low} Low</span>
                </span>
              </div>
            </div>
          </div>

          <button
            onClick={() => setShowExport(true)}
            className="shrink-0 mono text-[11px] border border-[#1e1c1c] px-3 py-1.5 text-[#535050] hover:text-[#f0eeed] hover:border-[#2a2828] transition-colors duration-150 flex items-center gap-1.5"
          >
            ↓ Export
          </button>
        </div>
      </header>

      {/* ── Filter bar ── */}
      <div className="shrink-0 border-b border-[#1e1c1c] flex items-center px-6">
        {FILTER_OPTIONS.map(({ key, label }) => {
          const count = filterCount(key);
          const disabled = key !== "All" && count === 0;
          return (
            <button
              key={key}
              onClick={() => !disabled && setFilter(key)}
              disabled={disabled}
              className={`
                py-3 mr-1 px-3 mono text-[11px] tracking-[0.04em] transition-colors duration-150 relative
                ${disabled ? "text-[#2a2828] cursor-default" : filter === key
                  ? "text-[#f0eeed]"
                  : "text-[#3a3836] hover:text-[#535050]"
                }
              `}
            >
              {filter === key && !disabled && (
                <span className="absolute bottom-0 left-0 right-0 h-[1.5px] bg-[#22d3a6]" />
              )}
              {label}
              <span className={`ml-1.5 ${filter === key && !disabled ? "text-[#535050]" : "text-[#2a2828]"}`}>
                {count}
              </span>
            </button>
          );
        })}
        <div className="ml-auto py-2">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search…"
            className="bg-[#111010] border border-[#1e1c1c] text-[#f0eeed] px-3 py-1.5 mono text-[11px] placeholder-[#3a3836] outline-none focus:border-[#22d3a6] transition-colors duration-150 w-[160px]"
          />
        </div>
      </div>

      {/* ── Split body ── */}
      <div className="flex flex-col md:flex-row flex-1 overflow-hidden">

        {/* Findings list */}
        <div className="w-full md:w-[52%] shrink-0 flex flex-col overflow-hidden max-h-[45%] md:max-h-none border-b md:border-b-0 md:border-r border-[#1e1c1c]">
          {/* Column header */}
          <div className="shrink-0 flex items-center px-4 py-2 border-b border-[#1e1c1c]">
            <span className="label-caps text-[#2a2828] w-[72px] shrink-0">Sev</span>
            <span className="label-caps text-[#2a2828] flex-1">Finding</span>
            <span className="label-caps text-[#2a2828] w-[50px] shrink-0 text-right hidden md:block">Module</span>
          </div>

          {/* Rows */}
          <div className="flex-1 overflow-y-auto">
            {filtered.length === 0 && (
              <p className="px-5 py-6 mono text-[11px] text-[#3a3836]">No findings match.</p>
            )}
            {filtered.map((f) => {
              const active = selectedId === f.id;
              return (
                <button
                  key={f.id}
                  onClick={() => select(f.id)}
                  style={{ borderLeftColor: SEV_COLORS[f.severity].bar }}
                  className={`
                    w-full text-left flex items-center border-b border-[#1e1c1c] border-l-2
                    pl-3.5 pr-4 py-3 transition-colors duration-150 relative
                    ${active ? "bg-[#151414]" : "hover:bg-[#0f0e0e]"}
                  `}
                >
                  <span className="w-[72px] shrink-0">
                    <SevBadge sev={f.severity} />
                  </span>
                  <span className="flex-1 min-w-0">
                    <span className="block text-[12px] text-[#f0eeed] leading-snug truncate">{f.name}</span>
                    <span className="block mono text-[10px] text-[#3a3836] mt-0.5 truncate">{f.path}</span>
                  </span>
                  <span className="w-[50px] shrink-0 text-right label-caps text-[#2a2828] hidden md:block">{f.module}</span>
                  {active && (
                    <span className="absolute right-0 top-0 bottom-0 w-[2px] bg-[#22d3a6]/30" />
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Detail panel */}
        <div className="flex-1 flex flex-col overflow-hidden min-w-0">
          {/* Finding identity */}
          <div className="shrink-0 px-6 py-4 border-b border-[#1e1c1c]">
            <div className="flex items-center gap-2 mb-2">
              <SevBadge sev={sel.severity} />
              <span className="mono text-[10px] text-[#3a3836]">{sel.module}</span>
              <span className="mono text-[10px] text-[#2a2828]">·</span>
              <span className={`mono text-[10px] ${sel.status === "New" ? "text-[#22d3a6]" : "text-[#3a3836]"}`}>
                {sel.status}
              </span>
            </div>
            <h2 className="text-[14px] font-semibold text-[#f0eeed] leading-snug mb-1.5">
              {sel.name}
            </h2>
            <p className="mono text-[10px] text-[#3a3836]">{sel.path}</p>
          </div>

          {/* Tabs */}
          <div className="shrink-0 flex border-b border-[#1e1c1c] px-6">
            {DETAIL_TABS.map(({ key, label }) => (
              <button
                key={key}
                onClick={() => setActiveTab(key)}
                className={`
                  py-2.5 mr-5 mono text-[11px] tracking-[0.06em] uppercase font-medium
                  border-b-[1.5px] -mb-px transition-colors duration-150
                  ${activeTab === key
                    ? "border-[#22d3a6] text-[#22d3a6]"
                    : "border-transparent text-[#3a3836] hover:text-[#535050]"
                  }
                `}
              >
                {label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div key={`${sel.id}-${activeTab}`} className="flex-1 overflow-y-auto p-6 fade-in">
            {activeTab === "what" && (
              <div className="space-y-4 max-w-[520px]">
                <p className="text-[13px] text-[#8a8785] leading-relaxed">{sel.what}</p>
              </div>
            )}

            {activeTab === "evidence" && (
              <div className="space-y-5 max-w-[520px]">
                <div>
                  <SectionLabel>How to verify</SectionLabel>
                  <p className="text-[13px] text-[#8a8785] leading-relaxed mb-3">{sel.howToCheck}</p>
                  <div className="bg-[#111010] border border-[#1e1c1c] px-4 py-3 flex items-start gap-3">
                    <span className="mono text-[11px] text-[#f0eeed] flex-1 break-all leading-relaxed">{sel.checkCommand}</span>
                    <CopyButton text={sel.checkCommand} className="shrink-0 mt-0.5" />
                  </div>
                </div>
                <div>
                  <SectionLabel>Scanner evidence</SectionLabel>
                  <div className="bg-[#111010] border border-[#1e1c1c] px-4 py-3 mono text-[11px] text-[#535050] break-all leading-relaxed">
                    {sel.evidence}
                  </div>
                </div>
              </div>
            )}

            {activeTab === "fix" && (
              <div className="space-y-4 max-w-[520px]">
                <p className="text-[13px] text-[#8a8785] leading-relaxed whitespace-pre-line">{sel.fix}</p>
              </div>
            )}

            {activeTab === "refs" && (
              <div className="space-y-3 max-w-[520px]">
                <div className="bg-[#111010] border border-[#1e1c1c] px-4 py-3 mono text-[12px] text-[#f0eeed]">
                  {sel.refs}
                </div>
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="shrink-0 border-t border-[#1e1c1c] px-6 py-3 flex items-center gap-2">
            <button className="mono text-[11px] border border-[#1e1c1c] px-3 py-1.5 text-[#535050] hover:text-[#f0eeed] hover:border-[#2a2828] transition-colors duration-150">
              Mark seen
            </button>
            <button className="mono text-[11px] px-3 py-1.5 text-[#3a3836] hover:text-[#535050] transition-colors duration-150">
              Ignore
            </button>
          </div>
        </div>
      </div>

      {showExport && <ExportModal onClose={() => setShowExport(false)} />}
    </div>
  );
}
