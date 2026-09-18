import { useState } from "react";

import { currentScan, reportUrl } from "@/data/api";

type Format = "PDF" | "Markdown" | "HTML" | "JSON";

const FORMATS: { key: Format; desc: string; ext: string; fmt: string }[] = [
  // PDF isn't a renderer yet — the HTML one is styled for browser print-to-PDF.
  { key: "PDF",      desc: "Print the HTML export",   ext: "pdf",  fmt: "html" },
  { key: "Markdown", desc: "Paste into a ticket",     ext: "md",   fmt: "md"   },
  { key: "HTML",     desc: "Open in any browser",     ext: "html", fmt: "html" },
  { key: "JSON",     desc: "Feed into other tools",   ext: "json", fmt: "json" },
];

const TOGGLES = [
  { id: "evidence",  label: "Include evidence"         },
  { id: "ignored",   label: "Include ignored findings" },
  { id: "redact",    label: "Redact target hostname"   },
];

export default function ExportModal({ onClose }: { onClose: () => void }) {
  const [format, setFormat] = useState<Format>("HTML");
  const [opts, setOpts] = useState({ evidence: true, ignored: false, redact: false });
  const [exporting, setExporting] = useState(false);

  const chosen = FORMATS.find((f) => f.key === format);
  const ext = chosen?.ext ?? "html";
  const job = currentScan();
  const href =
    job && job.state === "done" ? reportUrl(job.id, chosen?.fmt ?? "html") : null;

  function handleExport() {
    setExporting(true);
    if (href) {
      // The engine sets Content-Disposition, so this saves rather than navigates.
      const a = document.createElement("a");
      a.href = href;
      a.rel = "noopener";
      document.body.appendChild(a);
      a.click();
      a.remove();
    }
    setTimeout(onClose, 650);
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-[#0b0a0a]/85 backdrop-blur-[2px]"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="w-full max-w-[460px] bg-[#111010] border border-[#1e1c1c] mx-4">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e1c1c]">
          <h2 className="text-[14px] font-semibold text-[#f0eeed] tracking-[-0.01em]">Export report</h2>
          <button
            onClick={onClose}
            className="mono text-[#3a3836] hover:text-[#f0eeed] transition-colors duration-150 text-[14px] leading-none"
          >
            ✕
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Format */}
          <div>
            <p className="label-caps text-[#3a3836] mb-3">Format</p>
            <div className="grid grid-cols-2 gap-2">
              {FORMATS.map(({ key, desc }) => (
                <button
                  key={key}
                  onClick={() => setFormat(key)}
                  className={`
                    text-left p-3.5 border transition-all duration-150
                    ${format === key
                      ? "border-[#22d3a6] bg-[#22d3a6]/5"
                      : "border-[#1e1c1c] bg-[#181717] hover:border-[#2a2828]"
                    }
                  `}
                >
                  <span className={`block mono text-[12px] font-semibold mb-0.5 ${format === key ? "text-[#22d3a6]" : "text-[#f0eeed]"}`}>
                    {key}
                  </span>
                  <span className="block text-[11px] text-[#3a3836]">{desc}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Options */}
          <div className="space-y-3">
            <p className="label-caps text-[#3a3836]">Options</p>
            {TOGGLES.map(({ id, label }) => (
              <label key={id} className="flex items-center justify-between cursor-pointer">
                <span className="text-[13px] text-[#8a8785]">{label}</span>
                <button
                  role="switch"
                  aria-checked={opts[id as keyof typeof opts]}
                  onClick={() => setOpts((p) => ({ ...p, [id]: !p[id as keyof typeof opts] }))}
                  className={`w-7 h-4 relative transition-colors duration-200 ${opts[id as keyof typeof opts] ? "bg-[#22d3a6]" : "bg-[#1e1c1c]"}`}
                >
                  <span className={`absolute top-0.5 w-3 h-3 bg-[#0b0a0a] transition-transform duration-200 ${opts[id as keyof typeof opts] ? "translate-x-3.5" : "translate-x-0.5"}`} />
                </button>
              </label>
            ))}
          </div>

          {/* Output path */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <p className="label-caps text-[#3a3836]">Saves to</p>
              <span className="mono text-[10px] text-[#2a2828]">browser downloads</span>
            </div>
            <div className="bg-[#181717] border border-[#1e1c1c] px-4 py-2.5 mono text-[11px] text-[#535050]">
              {job ? `webscanx-${job.id}.${ext}` : `webscanx-report.${ext}`}
            </div>
            {!href && (
              <p className="mono text-[10px] text-[#eab308] mt-2 leading-relaxed">
                No finished scan to export — run a scan first.
              </p>
            )}
            {format === "PDF" && href && (
              <p className="mono text-[10px] text-[#535050] mt-2 leading-relaxed">
                Downloads the HTML report — open it and print to PDF.
              </p>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#1e1c1c]">
          <button
            onClick={onClose}
            className="text-[13px] text-[#535050] hover:text-[#f0eeed] transition-colors duration-150 px-4 py-2"
          >
            Cancel
          </button>
          <button
            onClick={handleExport}
            disabled={exporting}
            className="bg-[#22d3a6] text-[#0b0a0a] font-semibold text-[13px] px-6 py-2 hover:bg-[#1ec49a] transition-colors duration-150 disabled:opacity-50"
          >
            {exporting ? "Exporting…" : "Export"}
          </button>
        </div>
      </div>
    </div>
  );
}
