import { useState } from "react";

import { setCurrentScan, startScan } from "@/data/api";

type Depth = "Quick" | "Standard" | "Deep";

const DEPTHS: { key: Depth; time: string; desc: string }[] = [
  { key: "Quick", time: "~2 min", desc: "Headers & TLS only" },
  { key: "Standard", time: "~10 min", desc: "All modules, standard depth" },
  { key: "Deep", time: "~45 min", desc: "All modules, full crawl" },
];

// Each toggle maps to the engine scanners it switches off when unchecked.
const MODULES = [
  { id: "headers", label: "Security headers", scanners: ["web.headers", "web.csp"] },
  { id: "tls", label: "TLS / certificates", scanners: ["web.tls", "web.mixed"] },
  { id: "xss", label: "XSS", scanners: ["web.xss"] },
  { id: "sqli", label: "SQL injection", scanners: ["web.sqli"] },
  { id: "csrf", label: "CSRF & cookies", scanners: ["web.csrf", "web.cookies"] },
];

// Scan depth -> how hard the engine works. Quick is the two cheap checks.
const DEPTH_SETTINGS: Record<Depth, { only?: string[]; maxPages?: number; depth?: number }> = {
  Quick: { only: ["web.headers", "web.tls", "web.csp"], maxPages: 1, depth: 0 },
  Standard: {},
  Deep: { maxPages: 100, depth: 4 },
};

const RECENT = [
  "https://staging.example.com",
  "https://demo.webscanx.internal",
  "http://127.0.0.1:8000",
];

export default function NewScan() {
  const [target, setTarget] = useState("");
  const [depth, setDepth] = useState<Depth>("Standard");
  const [modules, setModules] = useState<Record<string, boolean>>(
    Object.fromEntries(MODULES.map((m) => [m.id, true]))
  );
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState("");
  const [starting, setStarting] = useState(false);

  async function handleStart() {
    if (starting) return;
    if (!target.trim()) {
      setError("Enter a full URL including https://");
      return;
    }
    try { new URL(target.trim()); }
    catch { setError("Enter a valid URL"); return; }
    setError("");
    setStarting(true);

    const exclude = MODULES.filter((m) => !modules[m.id]).flatMap((m) => m.scanners);
    try {
      const job = await startScan({
        target: target.trim(),
        kind: "web",
        authorized,
        exclude,
        ...DEPTH_SETTINGS[depth],
      });
      setCurrentScan(job);
      window.location.hash = "/dashboard/scanning";
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setStarting(false);
    }
  }

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-[580px] mx-auto px-8 py-10">

        {/* Page header */}
        <div className="mb-8">
          <h1 className="text-[22px] font-semibold tracking-[-0.02em] text-[#f0eeed]">New Scan</h1>
          <p className="text-[13px] text-[#535050] mt-1 leading-relaxed">
            Scan a target you own or have written authorization to test.
          </p>
        </div>

        <div className="space-y-6">
          {/* Target */}
          <div>
            <label className="label-caps text-[#535050] block mb-2">Target URL</label>
            <div className="relative">
              <input
                type="url"
                value={target}
                onChange={(e) => { setTarget(e.target.value); setError(""); }}
                onKeyDown={(e) => e.key === "Enter" && handleStart()}
                placeholder="https://staging.example.com"
                className={`
                  w-full bg-[#111010] border text-[#f0eeed] px-4 py-3
                  mono text-[13px] placeholder-[#353332] outline-none
                  transition-colors duration-150
                  focus:border-[#22d3a6]
                  ${error ? "border-[#ef4444]" : "border-[#1e1c1c]"}
                `}
              />
              {error && (
                <p className="mono text-[11px] text-[#ef4444] mt-1.5">{error}</p>
              )}
            </div>

            {/* Recent targets */}
            {RECENT.length > 0 && (
              <div className="flex flex-wrap items-center gap-2 mt-2.5">
                <span className="mono text-[10px] text-[#3a3836] tracking-[0.06em]">RECENT</span>
                {RECENT.map((url) => (
                  <button
                    key={url}
                    onClick={() => { setTarget(url); setError(""); }}
                    className="mono text-[10px] text-[#535050] hover:text-[#8a8785] border border-[#1e1c1c] px-2 py-0.5 transition-colors duration-150 hover:border-[#2a2828]"
                  >
                    {url.replace(/^https?:\/\//, "")}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Scan depth */}
          <div>
            <label className="label-caps text-[#535050] block mb-2">Scan Depth</label>
            <div className="grid grid-cols-3 gap-2">
              {DEPTHS.map(({ key, time, desc }) => (
                <button
                  key={key}
                  onClick={() => setDepth(key)}
                  className={`
                    text-left p-3.5 border transition-all duration-150
                    ${depth === key
                      ? "border-[#22d3a6] bg-[#22d3a6]/5"
                      : "border-[#1e1c1c] bg-[#111010] hover:border-[#2a2828]"
                    }
                  `}
                >
                  <span className={`block text-[13px] font-semibold mb-0.5 ${depth === key ? "text-[#22d3a6]" : "text-[#f0eeed]"}`}>
                    {key}
                  </span>
                  <span className="block mono text-[10px] text-[#535050] mb-0.5">{time}</span>
                  <span className="block text-[11px] text-[#3a3836]">{desc}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Modules */}
          <div>
            <label className="label-caps text-[#535050] block mb-2">Modules</label>
            <div className="border border-[#1e1c1c] bg-[#111010] divide-y divide-[#1e1c1c]">
              {MODULES.map((mod) => (
                <label
                  key={mod.id}
                  className="flex items-center justify-between px-4 py-2.5 cursor-pointer hover:bg-[#151414] transition-colors duration-150"
                >
                  <span className="text-[13px] text-[#8a8785]">{mod.label}</span>
                  <div
                    onClick={() => setModules((p) => ({ ...p, [mod.id]: !p[mod.id] }))}
                    role="switch"
                    aria-checked={modules[mod.id]}
                    className={`
                      w-7 h-4 relative cursor-pointer transition-colors duration-200
                      ${modules[mod.id] ? "bg-[#22d3a6]" : "bg-[#1e1c1c]"}
                    `}
                  >
                    <span className={`
                      absolute top-0.5 w-3 h-3 bg-[#0b0a0a] transition-transform duration-200
                      ${modules[mod.id] ? "translate-x-3.5" : "translate-x-0.5"}
                    `} />
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Authorization gate */}
          <div className={`
            border p-5 transition-all duration-200
            ${authorized
              ? "border-[#22d3a6]/30 bg-[#22d3a6]/4"
              : "border-[#2a2828] bg-[#111010]"
            }
          `}>
            <label className="flex items-start gap-3.5 cursor-pointer">
              <div className="mt-0.5 shrink-0">
                <input
                  type="checkbox"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                  className="sr-only"
                />
                <div
                  onClick={() => setAuthorized((v) => !v)}
                  className={`
                    w-4 h-4 border flex items-center justify-center transition-all duration-150
                    ${authorized
                      ? "bg-[#22d3a6] border-[#22d3a6]"
                      : "bg-transparent border-[#2a2828] hover:border-[#535050]"
                    }
                  `}
                >
                  {authorized && (
                    <svg width="9" height="7" viewBox="0 0 9 7" fill="none">
                      <path d="M1 3.5L3.5 6L8 1" stroke="#0b0a0a" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  )}
                </div>
              </div>
              <div>
                <span className="block text-[13px] font-semibold text-[#f0eeed] leading-snug">
                  I am authorized to scan this target
                </span>
                <span className="block text-[12px] text-[#535050] mt-1.5 leading-relaxed">
                  Scanning systems without authorization may be illegal in your jurisdiction.
                  Only test targets you own or have explicit written permission to test.
                </span>
              </div>
            </label>
          </div>

          {/* Start button */}
          <button
            onClick={handleStart}
            disabled={!authorized || starting}
            className={`
              w-full py-3.5 text-[13px] font-semibold tracking-[0.02em] transition-all duration-200
              ${authorized && !starting
                ? "bg-[#22d3a6] text-[#0b0a0a] hover:bg-[#1ec49a] cursor-pointer"
                : "bg-[#1e1c1c] text-[#3a3836] cursor-not-allowed"
              }
            `}
          >
            {!authorized ? "Authorize scan to continue" : starting ? "Starting…" : "Start Scan →"}
          </button>
        </div>
      </div>
    </div>
  );
}
