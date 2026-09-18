import { useState, type ReactNode } from "react";

type Depth = "Quick" | "Standard" | "Deep";

const MODULES = [
  { id: "headers", label: "Security headers" },
  { id: "tls", label: "TLS / certificates" },
  { id: "xss", label: "XSS" },
  { id: "sqli", label: "SQL injection" },
  { id: "csrf", label: "CSRF & cookies" },
];

function load<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v ? (JSON.parse(v) as T) : fallback;
  } catch { return fallback; }
}

function Section({ label, description, children }: { label: string; description?: string; children: ReactNode }) {
  return (
    <div className="py-6 border-b border-[#1e1c1c] last:border-b-0">
      <div className="flex flex-col md:flex-row md:items-start gap-3 md:gap-8">
        <div className="w-full md:w-[180px] shrink-0">
          <p className="text-[13px] font-semibold text-[#f0eeed] mb-0.5">{label}</p>
          {description && <p className="text-[12px] text-[#3a3836] leading-relaxed mt-1">{description}</p>}
        </div>
        <div className="flex-1">{children}</div>
      </div>
    </div>
  );
}

export default function Settings() {
  const [depth, setDepth] = useState<Depth>(() => load<Depth>("ws_depth", "Standard"));
  const [modules, setModules] = useState<Record<string, boolean>>(
    () => load("ws_modules", Object.fromEntries(MODULES.map((m) => [m.id, true])))
  );
  const [rateLimit, setRateLimit] = useState(() => load<string>("ws_rate", "10"));
  const [saved, setSaved] = useState(false);

  function handleSave() {
    localStorage.setItem("ws_depth", JSON.stringify(depth));
    localStorage.setItem("ws_modules", JSON.stringify(modules));
    localStorage.setItem("ws_rate", JSON.stringify(rateLimit));
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  function toggleModule(id: string) {
    setModules((p) => ({ ...p, [id]: !p[id] }));
  }

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-[720px] px-5 md:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-[22px] font-semibold tracking-[-0.02em] text-[#f0eeed]">Settings</h1>
          <p className="text-[13px] text-[#535050] mt-1">Defaults applied to every new scan.</p>
        </div>

        <div className="border border-[#1e1c1c] px-6">
          {/* Scan depth */}
          <Section label="Default scan depth" description="Applied to every new scan unless overridden.">
            <div className="flex gap-0 border border-[#1e1c1c]">
              {(["Quick", "Standard", "Deep"] as Depth[]).map((d, i, arr) => (
                <button
                  key={d}
                  onClick={() => setDepth(d)}
                  className={`
                    flex-1 py-2.5 text-[13px] font-medium transition-colors duration-150
                    ${i < arr.length - 1 ? "border-r border-[#1e1c1c]" : ""}
                    ${depth === d
                      ? "bg-[#22d3a6] text-[#0b0a0a]"
                      : "bg-[#111010] text-[#535050] hover:text-[#f0eeed]"
                    }
                  `}
                >
                  {d}
                </button>
              ))}
            </div>
          </Section>

          {/* Modules */}
          <Section label="Default modules" description="Modules enabled for new scans by default.">
            <div className="border border-[#1e1c1c] divide-y divide-[#1e1c1c]">
              {MODULES.map((mod) => (
                <label key={mod.id} className="flex items-center justify-between px-4 py-2.5 cursor-pointer hover:bg-[#151414] transition-colors duration-150">
                  <span className="text-[13px] text-[#8a8785]">{mod.label}</span>
                  <button
                    role="switch"
                    aria-checked={modules[mod.id]}
                    onClick={() => toggleModule(mod.id)}
                    className={`w-7 h-4 relative transition-colors duration-200 ${modules[mod.id] ? "bg-[#22d3a6]" : "bg-[#1e1c1c]"}`}
                  >
                    <span className={`absolute top-0.5 w-3 h-3 bg-[#0b0a0a] transition-transform duration-200 ${modules[mod.id] ? "translate-x-3.5" : "translate-x-0.5"}`} />
                  </button>
                </label>
              ))}
            </div>
          </Section>

          {/* Report folder */}
          <Section label="Report folder" description="Where exported reports are saved.">
            <div className="flex items-center gap-3">
              <span className="flex-1 mono text-[12px] text-[#535050] bg-[#111010] border border-[#1e1c1c] px-4 py-2.5">
                ~/Documents/webscanx-reports/
              </span>
              <button className="mono text-[11px] border border-[#1e1c1c] px-3 py-2.5 text-[#535050] hover:text-[#f0eeed] hover:border-[#2a2828] transition-colors duration-150 shrink-0">
                Change
              </button>
            </div>
          </Section>

          {/* Rate limit */}
          <Section label="Request rate" description="Max HTTP requests per second during a scan.">
            <div className="flex items-center gap-3">
              <input
                type="number"
                value={rateLimit}
                onChange={(e) => setRateLimit(e.target.value)}
                min="1" max="100"
                className="w-20 bg-[#111010] border border-[#1e1c1c] text-[#f0eeed] px-3 py-2.5 mono text-[13px] outline-none focus:border-[#22d3a6] transition-colors duration-150 text-center"
              />
              <span className="mono text-[12px] text-[#535050]">requests / second</span>
            </div>
          </Section>

          {/* Theme */}
          <Section label="Theme" description="The interface runs in dark mode only.">
            <div className="flex items-center gap-2 mono text-[12px] text-[#3a3836]">
              <span className="w-2 h-2 bg-[#0b0a0a] border border-[#2a2828]" />
              Dark only
            </div>
          </Section>
        </div>

        {/* Save */}
        <div className="mt-6 flex items-center gap-4">
          <button
            onClick={handleSave}
            className="bg-[#22d3a6] text-[#0b0a0a] font-semibold text-[13px] px-6 py-3 hover:bg-[#1ec49a] transition-colors duration-150"
          >
            {saved ? "✓ Saved" : "Save settings"}
          </button>
          {saved && (
            <span className="mono text-[11px] text-[#22d3a6] fade-in">Changes applied</span>
          )}
        </div>
      </div>
    </div>
  );
}
