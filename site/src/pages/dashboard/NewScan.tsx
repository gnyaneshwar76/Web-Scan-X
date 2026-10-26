import { useState } from "react";

import { setCurrentScan, startScan, type AiMode } from "@/data/api";

type TargetKind = "web" | "app" | "code";

const TARGET_KINDS: { key: TargetKind; label: string; hint: string; placeholder: string }[] = [
  { key: "web", label: "Website", hint: "Target URL", placeholder: "https://staging.example.com" },
  { key: "app", label: "App or program file", hint: "Full path to the file (.apk .aab .ipa .exe .dll .msi .sys .pkg .dmg, or a .app folder)", placeholder: "C:\\Users\\you\\Downloads\\my-app.apk" },
  { key: "code", label: "Source code folder", hint: "Full path to a folder of your own source code", placeholder: "C:\\Users\\you\\projects\\my-site" },
];

const AI_MODES: { key: AiMode; label: string; desc: string }[] = [
  { key: "off", label: "Off", desc: "Default. No AI is used." },
  { key: "local", label: "Local", desc: "Ollama on this computer. Nothing leaves it." },
  { key: "cloud", label: "Cloud (opt-in)", desc: "Sends a redacted summary of findings to Anthropic." },
];

const APP_EXT = /\.(apk|aab|ipa|exe|dll|msi|sys|pkg|dmg)$/i;
const ABS_PATH = /^([a-zA-Z]:[\\/]|\\\\|\/)/;

function stored<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v ? (JSON.parse(v) as T) : fallback;
  } catch { return fallback; }
}

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
  const [kind, setKind] = useState<TargetKind>("web");
  const [ai, setAi] = useState<AiMode>(() => stored<AiMode>("ws_ai", "off"));
  const [aiPlan, setAiPlan] = useState(false);
  const kindInfo = TARGET_KINDS.find((k) => k.key === kind)!;
  const [depth, setDepth] = useState<Depth>("Standard");
  const [modules, setModules] = useState<Record<string, boolean>>(
    Object.fromEntries(MODULES.map((m) => [m.id, true]))
  );
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState("");
  const [starting, setStarting] = useState(false);

  async function handleStart() {
    if (starting) return;
    const t = target.trim();
    if (!t) {
      setError(kind === "web" ? "Enter a full URL including https://" : "Enter the full path");
      return;
    }
    if (kind === "web") {
      try { new URL(t); }
      catch { setError("Enter a valid URL"); return; }
    } else if (!ABS_PATH.test(t)) {
      setError("Enter an absolute path, e.g. C:\\folder\\file or /home/you/file");
      return;
    } else if (kind === "app" && !APP_EXT.test(t) && !/\.app[\\/]*$/i.test(t)) {
      setError("Unsupported file type. Use .apk .aab .ipa .exe .dll .msi .sys .pkg .dmg or a .app folder");
      return;
    }
    setError("");
    setStarting(true);

    const exclude = MODULES.filter((m) => !modules[m.id]).flatMap((m) => m.scanners);
    try {
      const job = await startScan({
        target: target.trim(),
        authorized,
        ai,
        ...(ai !== "off" ? { aiModel: stored<string>("ws_ai_model", "") || undefined } : {}),
        ...(kind === "code" ? { kind: "code" as const } : {}),
        ...(kind === "web"
          ? { kind: "web" as const, exclude, ...DEPTH_SETTINGS[depth], ...(ai !== "off" && aiPlan ? { aiPlan: true } : {}) }
          : {}),
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
            Scan a website, app file or source code you own or have written authorization to test.
          </p>
        </div>

        <div className="space-y-6">
          {/* Target */}
          <div>
            <label className="label-caps text-[#535050] block mb-2">Target type</label>
            <div className="grid grid-cols-3 gap-2 mb-5">
              {TARGET_KINDS.map((k) => (
                <button
                  key={k.key}
                  onClick={() => { setKind(k.key); setTarget(""); setError(""); }}
                  className={`text-left p-3 border text-[13px] font-semibold transition-all duration-150 ${kind === k.key ? "border-[#22d3a6] bg-[#22d3a6]/5 text-[#22d3a6]" : "border-[#1e1c1c] bg-[#111010] text-[#f0eeed] hover:border-[#2a2828]"}`}
                >
                  {k.label}
                </button>
              ))}
            </div>
            <label className="label-caps text-[#535050] block mb-2">{kind === "web" ? "Target URL" : "Path"}</label>
            {kind !== "web" && <p className="text-[11px] text-[#535050] mb-2 leading-relaxed">{kindInfo.hint}</p>}
            <div className="relative">
              <input
                type={kind === "web" ? "url" : "text"}
                value={target}
                onChange={(e) => { setTarget(e.target.value); setError(""); }}
                onKeyDown={(e) => e.key === "Enter" && handleStart()}
                placeholder={kindInfo.placeholder}
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
            {kind === "web" && RECENT.length > 0 && (
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

          {/* AI helper */}
          <div>
            <label className="label-caps text-[#535050] block mb-2">AI helper</label>
            <div className="grid grid-cols-3 gap-2">
              {AI_MODES.map((m) => (
                <button
                  key={m.key}
                  onClick={() => setAi(m.key)}
                  className={`text-left p-3 border transition-all duration-150 ${ai === m.key ? "border-[#22d3a6] bg-[#22d3a6]/5" : "border-[#1e1c1c] bg-[#111010] hover:border-[#2a2828]"}`}
                >
                  <span className={`block text-[13px] font-semibold mb-0.5 ${ai === m.key ? "text-[#22d3a6]" : "text-[#f0eeed]"}`}>{m.label}</span>
                  <span className="block text-[11px] text-[#3a3836]">{m.desc}</span>
                </button>
              ))}
            </div>
            <p className="text-[11px] text-[#535050] mt-2 leading-relaxed">
              The AI never decides what is a vulnerability. It only comments on findings the normal checks already made.
              {ai === "cloud" && " Cloud mode sends a redacted summary of the findings to Anthropic and needs ANTHROPIC_API_KEY set where the engine runs."}
              {ai === "local" && " Local mode needs Ollama running on this computer."}
            </p>
            {kind === "web" && ai !== "off" && (
              <label className="flex items-center gap-2 mt-3 text-[12px] text-[#8a8785] cursor-pointer">
                <input type="checkbox" checked={aiPlan} onChange={(e) => setAiPlan(e.target.checked)} />
                Let AI choose checks
              </label>
            )}
          </div>

          {/* Scan depth */}
          {kind === "web" && (
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

          )}

          {/* Modules */}
          {kind === "web" && (
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

          )}

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
                  {kind === "web"
                    ? "I own this target or have written permission to test it, and I accept responsibility."
                    : kind === "app"
                      ? "I own this file or have the right to analyze it."
                      : "I own this code or have the right to analyze it."}{" "}
                  <a href="https://github.com/gnyaneshwar76/Web-Scan-X/blob/main/docs/policy/ACCEPTABLE-USE.md" target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()} className="underline text-[#7fe0b8]">Acceptable Use</a>
                </span>
                <span className="block text-[11px] text-[#535050] mt-1.5 leading-relaxed">
                  I own this target or have written permission to test it, and I will stay within the scope I am authorized for. I will not scan third-party systems. I understand aggressive mode can send requests that change or delete data. I accept full responsibility for this scan.
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
