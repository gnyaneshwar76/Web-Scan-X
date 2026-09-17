import { useState } from "react";

type Format = "PDF" | "Markdown" | "HTML" | "JSON";

const FORMATS: { key: Format; desc: string; ext: string }[] = [
  { key: "PDF",      desc: "Share with a client",     ext: "pdf" },
  { key: "Markdown", desc: "Paste into a ticket",     ext: "md"  },
  { key: "HTML",     desc: "Open in any browser",     ext: "html" },
  { key: "JSON",     desc: "Feed into other tools",   ext: "json" },
];

const TOGGLES = [
  { id: "evidence",  label: "Include evidence"         },
  { id: "ignored",   label: "Include ignored findings" },
  { id: "redact",    label: "Redact target hostname"   },
];

export default function ExportModal({ onClose }: { onClose: () => void }) {
  const [format, setFormat] = useState<Format>("PDF");
  const [opts, setOpts] = useState({ evidence: true, ignored: false, redact: false });
  const [exporting, setExporting] = useState(false);

  const ext = FORMATS.find((f) => f.key === format)?.ext ?? "pdf";

  function handleExport() {
    setExporting(true);
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
              <p className="label-caps text-[#3a3836]">Output path</p>
              <button className="mono text-[10px] text-[#2a2828] hover:text-[#535050] transition-colors duration-150">Change</button>
            </div>
            <div className="bg-[#181717] border border-[#1e1c1c] px-4 py-2.5 mono text-[11px] text-[#535050]">
              ~/Documents/webscanx-report-2026-09-15.{ext}
            </div>
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
