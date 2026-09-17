import { useState } from "react";
import CopyButton from "@/components/CopyButton";
import SevPill from "@/components/SevPill";
import { FINDINGS, SCAN_META, SEV_COLORS, type Finding } from "@/data/findings";

type Platform = "win" | "mac" | "linux";

const platformData: Record<Platform, { label: string; meta: string; exe: string; size: string; checksum: string }> = {
  win: { label: "Download for Windows", meta: "v1.0 · 24 MB (.exe)", exe: ".exe", size: "24 MB · Windows 10/11", checksum: "8f4b2a67e1093120b6017b29e0992389104c8f4b2a67e109" },
  mac: { label: "Download for macOS", meta: "v1.0 · 28 MB (.dmg)", exe: ".dmg", size: "28 MB · Apple Silicon + Intel", checksum: "3c7a188ffa8200192837bc9012384a823c7a188ffa82" },
  linux: { label: "Download for Linux", meta: "v1.0 · 22 MB (.AppImage)", exe: ".AppImage", size: "22 MB · x86_64", checksum: "d5a26ba677b189283749281728392019d5a26ba677b1" },
};

function Nav({ platform }: { platform: Platform; setPlatform: (p: Platform) => void }) {
  void platform;
  return (
    <header className="fixed top-0 left-0 right-0 z-40 bg-[#0d0c0c]/85 backdrop-blur-md border-b border-[#2a2828]/50">
      <div className="max-w-[1200px] mx-auto px-6 h-16 flex items-center justify-between">
        <a href="#" className="mono text-base font-semibold tracking-tight text-[#f2f0ef] hover:text-white flex items-center gap-2">
          WebScanX
        </a>
        <nav className="hidden md:flex items-center gap-8 text-sm text-[#9a9695] font-medium">
          <a href="#how-it-works" className="hover:text-[#f2f0ef] transition-colors">How it works</a>
          <a href="#what-it-checks" className="hover:text-[#f2f0ef] transition-colors">What it checks</a>
          <a href="#sample-report" className="hover:text-[#f2f0ef] transition-colors">Sample report</a>
          <a href="#faq" className="hover:text-[#f2f0ef] transition-colors">Docs</a>
          <a href="https://github.com" target="_blank" rel="noreferrer" className="hover:text-[#f2f0ef] transition-colors">GitHub</a>
        </nav>
        <a href="#download" className="inline-flex items-center justify-center bg-[#22d3a6] text-[#0d0c0c] font-semibold text-xs tracking-wider uppercase px-4 py-2 hover:bg-[#20c298] transition-colors whitespace-nowrap">
          Download
        </a>
      </div>
    </header>
  );
}

function Hero({ platform, setPlatform }: { platform: Platform; setPlatform: (p: Platform) => void }) {
  const d = platformData[platform];
  return (
    <section className="relative min-h-[calc(100vh-4rem)] flex flex-col items-center justify-start pt-24 pb-12 overflow-hidden">
      <div className="absolute inset-0 pointer-events-none hero-haze" />
      <div className="absolute inset-0 pointer-events-none film-grain opacity-60" />
      <div className="relative z-10 max-w-[1200px] w-full mx-auto px-6 flex flex-col items-center text-center">
        <p className="mono text-xs tracking-widest text-[#9a9695] uppercase mb-6">OPEN-SOURCE · RUNS 100% LOCALLY</p>
        <h1 className="text-5xl sm:text-7xl lg:text-[96px] font-bold tracking-tighter leading-[0.98] text-[#f2f0ef] max-w-[1000px] mb-8">
          Find your vulnerabilities <br />
          <span className="text-[#9a9695]">before they do.</span>
        </h1>
        <p className="text-lg sm:text-xl text-[#9a9695] max-w-[560px] font-normal leading-relaxed mb-10">
          A local scanner that finds web vulnerabilities and explains each one in plain language. Nothing leaves your device.
        </p>

        <div className="flex flex-col items-center gap-4 mb-16">
          <div className="flex flex-wrap items-center justify-center gap-4">
            <div className="flex items-center gap-3">
              <a href="#download" className="inline-flex items-center justify-center bg-[#22d3a6] text-[#0d0c0c] font-semibold text-sm tracking-wide px-6 py-3.5 hover:bg-[#20c298] transition-colors whitespace-nowrap">
                {d.label}
              </a>
              <span className="mono text-xs text-[#9a9695] tracking-tight">{d.meta}</span>
            </div>
            <a
              href="#/dashboard/new-scan"
              className="text-sm font-medium text-[#9a9695] hover:text-[#f2f0ef] inline-flex items-center gap-1.5 transition-colors group px-2 py-3.5"
            >
              <span>Try the dashboard</span>
              <span className="group-hover:translate-x-1 transition-transform">→</span>
            </a>
          </div>
          <div className="flex items-center gap-1.5 p-1 bg-[#151414] border border-[#2a2828] mono text-[11px]">
            <span className="text-[#605d5d] px-2 py-0.5">Platform:</span>
            {(["win", "mac", "linux"] as Platform[]).map((p) => (
              <button
                key={p}
                onClick={() => setPlatform(p)}
                className={`px-2.5 py-0.5 transition-colors ${platform === p ? "bg-[#1c1b1b] text-[#22d3a6] font-medium border border-[#2a2828]/80" : "text-[#9a9695] hover:text-[#f2f0ef]"}`}
              >
                {p === "win" ? "Windows" : p === "mac" ? "macOS" : "Linux"}
              </button>
            ))}
          </div>
        </div>

        <div className="w-full perspective-stage mt-2">
          <div
            className="product-tilt border border-[#2a2828] bg-[#151414] text-left overflow-hidden relative"
            style={{ maskImage: "linear-gradient(to bottom, black 82%, transparent 100%)", WebkitMaskImage: "linear-gradient(to bottom, black 82%, transparent 100%)" }}
          >
            <div className="h-10 border-b border-[#2a2828] bg-[#1c1b1b]/80 px-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 bg-[#ef4444]/60" />
                <span className="w-2.5 h-2.5 bg-[#eab308]/60" />
                <span className="w-2.5 h-2.5 bg-[#22d3a6]/60" />
                <div className="flex items-center gap-2 ml-3">
                  <span className="w-2 h-2 bg-[#22d3a6] animate-ping" />
                  <span className="mono text-[10px] px-2 py-0.5 bg-[#0d0c0c] border border-[#2a2828] text-[#22d3a6] font-semibold tracking-wider">SCANNING // RUNNING</span>
                </div>
              </div>
              <div className="flex items-center gap-4 mono text-xs text-[#605d5d]">
                <span className="hidden sm:inline"><span className="text-[#605d5d]">TARGET:</span> <span className="text-[#f2f0ef] font-medium">https://staging.example.com</span></span>
                <span className="text-[#9a9695] border-l border-[#2a2828] pl-3"><span className="text-[#605d5d]">ELAPSED:</span> 04:12</span>
                <button className="mono text-[11px] px-2.5 py-0.5 border border-[#2a2828] bg-[#151414] text-[#9a9695] hover:text-white hover:border-[#9a9695] transition-colors ml-2">Stop scan</button>
              </div>
            </div>

            <div className="border-b border-[#2a2828] bg-[#0d0c0c]/85 px-4 py-2.5 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2 mono text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 bg-[#22d3a6]" />
                  <span className="text-[#f2f0ef] font-medium">Checking XSS — reflected parameters</span>
                  <span className="text-[#9a9695]">(38 / 61 requests)</span>
                </div>
                <span className="text-[#22d3a6] font-semibold">62%</span>
              </div>
              <div className="w-full h-1.5 bg-[#1c1b1b] overflow-hidden">
                <div className="h-full bg-[#22d3a6]" style={{ width: "62%" }} />
              </div>
              <div className="flex flex-wrap items-center gap-2 pt-1 mono text-[11px]">
                <span className="px-2 py-0.5 bg-[#1c1b1b] border border-[#2a2828] text-[#9a9695] flex items-center gap-1"><span className="text-[#22d3a6]">✓</span> Security headers</span>
                <span className="px-2 py-0.5 bg-[#1c1b1b] border border-[#2a2828] text-[#9a9695] flex items-center gap-1"><span className="text-[#22d3a6]">✓</span> TLS / certificates</span>
                <span className="px-2 py-0.5 bg-[#22d3a6]/15 border border-[#22d3a6]/40 text-[#22d3a6] font-medium flex items-center gap-1"><span className="w-1.5 h-1.5 bg-[#22d3a6] inline-block" /> XSS (Active)</span>
                <span className="px-2 py-0.5 bg-[#151414] border border-[#2a2828]/50 text-[#605d5d]">SQL injection · Queued</span>
                <span className="hidden sm:inline-block px-2 py-0.5 bg-[#151414] border border-[#2a2828]/50 text-[#605d5d]">CSRF & cookies · Queued</span>
              </div>
            </div>

            <div className="border-b border-[#2a2828] bg-[#151414] px-4 py-2 flex flex-wrap items-center gap-4 mono text-xs">
              <span className="text-[#605d5d] uppercase tracking-wider text-[11px]">LIVE FINDINGS:</span>
              <span style={{ color: SEV_COLORS.HIGH.bar }} className="text-[11px]">HIGH <span className="font-bold">2</span></span>
              <span style={{ color: SEV_COLORS.MEDIUM.bar }} className="text-[11px]">MED <span className="font-bold">1</span></span>
              <span style={{ color: SEV_COLORS.LOW.bar }} className="text-[11px]">LOW <span className="font-bold">3</span></span>
            </div>

            <div className="p-4 space-y-2 bg-[#151414]">
              <div className="flex items-center justify-between pb-2 border-b border-[#2a2828]/60 mono text-[11px]">
                <span className="text-[#9a9695] font-medium">DETECTED IN REAL TIME (NEWEST FIRST)</span>
                <span className="text-[#605d5d]">5 of 6 shown</span>
              </div>
              <div className="space-y-1.5 mono text-[11px]">
                {[
                  { sev: "HIGH" as const, name: "Reflected XSS", path: "/?q= (param: q)", time: "04:09", active: true },
                  { sev: "MEDIUM" as const, name: "Missing Content-Security-Policy header", path: "/", time: "03:51" },
                  { sev: "HIGH" as const, name: "Site served over HTTP (no TLS)", path: "http://127.0.0.1:63725", time: "03:40" },
                  { sev: "LOW" as const, name: "Missing X-Content-Type-Options header", path: "/", time: "02:18" },
                  { sev: "LOW" as const, name: "Missing X-Frame-Options header", path: "/", time: "01:02" },
                ].map((f, i) => (
                  <div key={i} style={{ borderLeftColor: f.active ? "#22d3a6" : "transparent" }} className={`p-2.5 border-l-2 flex items-center justify-between transition-colors ${f.active ? "bg-[#1c1b1b]" : "border-transparent text-[#9a9695] hover:bg-[#1c1b1b]/40"}`}>
                    <div className="flex items-center gap-3 truncate">
                      <SevPill level={f.sev} />
                      <span className="font-sans font-medium text-[#f2f0ef]">{f.name}</span>
                    </div>
                    <div className="flex items-center gap-3 text-[#605d5d] ml-2 shrink-0">
                      <span className="text-[#9a9695] hidden sm:block">{f.path}</span>
                      <span className={`text-[10px] ${f.active ? "text-[#22d3a6] font-mono" : ""}`}>{f.time}</span>
                    </div>
                  </div>
                ))}
              </div>
              <div className="p-2 text-[#605d5d] text-[11px] mono border-t border-[#2a2828]/50 pt-3 mt-3">
                + 1 more findings
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Statement() {
  const items = ["SECURITY HEADERS", "TLS", "XSS", "SQL INJECTION", "CSRF", "COOKIES", "CORS", "CSP", "OPEN REDIRECTS"];
  const doubled = [...items, ...items];
  return (
    <section className="py-24 sm:py-36 max-w-[1200px] mx-auto px-6 text-center">
      <h2 className="text-3xl sm:text-5xl lg:text-[48px] font-medium tracking-tight leading-[1.25] max-w-[900px] mx-auto mb-16">
        <span className="text-[#f2f0ef] font-semibold">WebScanX finds web vulnerabilities</span>,{" "}
        <span className="text-[#605d5d]">explains them</span>{" "}
        <span className="text-[#f2f0ef] font-semibold">like a colleague would</span>,{" "}
        <span className="text-[#605d5d]">and</span>{" "}
        <span className="text-[#f2f0ef] font-semibold">never sends a byte off your machine</span>.
      </h2>
      <div className="w-full overflow-hidden relative">
        <div className="animate-marquee gap-12 mono text-sm text-[#605d5d] tracking-widest uppercase">
          {doubled.map((item, i) => (
            <span key={i} className="mr-12">{item} <span className="text-[#2a2828] mr-12">•</span></span>
          ))}
        </div>
      </div>
    </section>
  );
}

function HowItWorks() {
  return (
    <section id="how-it-works" className="py-20 sm:py-32 max-w-[1200px] mx-auto px-6">
      <div className="mb-16">
        <p className="mono text-xs tracking-widest text-[#9a9695] uppercase mb-4">HOW IT WORKS</p>
        <h2 className="text-4xl sm:text-[56px] font-bold tracking-tight text-[#f2f0ef] leading-[1.05]">
          Three steps. No account. No cloud.
        </h2>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-10 lg:gap-14">
        <div className="pt-8 border-t border-[#2a2828] flex flex-col justify-between h-full">
          <div>
            <div className="mono text-2xl font-bold text-[#605d5d] mb-4">01</div>
            <h3 className="text-2xl font-bold text-[#f2f0ef] mb-3">Download</h3>
            <p className="text-base text-[#9a9695] leading-relaxed mb-8">
              One file for your system, or pip install. Nothing else to install.
            </p>
          </div>
          <div className="bg-[#151414] border border-[#2a2828] p-4 mono text-xs text-[#f2f0ef] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-[#9a9695]">$</span>
              <span>webscanx start</span>
            </div>
            <CopyButton text="webscanx start" />
          </div>
        </div>

        <div className="pt-8 border-t border-[#2a2828] flex flex-col justify-between h-full">
          <div>
            <div className="mono text-2xl font-bold text-[#605d5d] mb-4">02</div>
            <h3 className="text-2xl font-bold text-[#f2f0ef] mb-3">Point it at your site</h3>
            <p className="text-base text-[#9a9695] leading-relaxed mb-8">
              Paste a URL you&apos;re allowed to test and confirm you&apos;re authorized.
            </p>
          </div>
          <div className="bg-[#151414] border border-[#2a2828] p-4 space-y-3">
            <div className="bg-[#0d0c0c] border border-[#2a2828] px-3 py-2 mono text-xs text-[#9a9695] flex items-center justify-between">
              <span>https://staging.example.com</span>
              <span className="w-1.5 h-1.5 bg-[#605d5d]" />
            </div>
            <label className="flex items-center gap-2.5 text-xs text-[#9a9695] cursor-pointer select-none">
              <input
                type="checkbox"
                defaultChecked
                className="w-3.5 h-3.5 cursor-pointer bg-[#0d0c0c] border-[#2a2828] accent-[#22d3a6]"
              />
              <span>I am authorized to scan this target</span>
            </label>
          </div>
        </div>

        <div className="pt-8 border-t border-[#2a2828] flex flex-col justify-between h-full">
          <div>
            <div className="mono text-2xl font-bold text-[#605d5d] mb-4">03</div>
            <h3 className="text-2xl font-bold text-[#f2f0ef] mb-3">Read the report</h3>
            <p className="text-base text-[#9a9695] leading-relaxed mb-8">
              Every finding explained: what it is, how to check it, how to fix it.
            </p>
          </div>
          <div className="bg-[#151414] border border-[#2a2828] p-3 space-y-2 mono text-xs">
            {[
              { sev: "HIGH" as const, name: "Reflected XSS", path: "/search" },
              { sev: "MEDIUM" as const, name: "Cookie without Secure flag", path: "/login" },
              { sev: "LOW" as const, name: "Missing X-Content-Type", path: "/" },
            ].map((f, i, arr) => (
              <div key={i} className={`flex items-center justify-between py-1 ${i < arr.length - 1 ? "border-b border-[#2a2828]/50" : ""}`}>
                <div className="flex items-center gap-2">
                  <SevPill level={f.sev} />
                  <span className="font-sans text-xs text-[#f2f0ef]">{f.name}</span>
                </div>
                <span className="text-[11px] text-[#605d5d]">{f.path}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

type SampleTab = "what" | "evidence" | "fix" | "refs";
const SAMPLE_TABS: { key: SampleTab; label: string }[] = [
  { key: "what", label: "What" },
  { key: "evidence", label: "Evidence" },
  { key: "fix", label: "Fix" },
  { key: "refs", label: "Refs" },
];
const { counts } = SCAN_META;
const SAMPLE_TOTAL = counts.high + counts.medium + counts.low;

function SampleReport() {
  const [selectedId, setSelectedId] = useState(FINDINGS[0].id);
  const [activeTab, setActiveTab] = useState<SampleTab>("what");

  function select(id: number) { setSelectedId(id); setActiveTab("what"); }

  const sel: Finding = FINDINGS.find((f) => f.id === selectedId) ?? FINDINGS[0];

  return (
    <section id="sample-report" className="py-20 sm:py-32 max-w-[1200px] mx-auto px-6">
      <div className="text-center mb-12">
        <p className="mono text-xs tracking-widest text-[#9a9695] uppercase mb-3">SAMPLE REPORT</p>
        <h2 className="text-4xl sm:text-[56px] font-bold tracking-tight text-[#f2f0ef] mb-4">This is exactly what you get.</h2>
        <p className="text-base sm:text-lg text-[#9a9695] max-w-[600px] mx-auto">A real scan of a local target. Nothing staged.</p>
      </div>

      <div className="border border-[#2a2828] bg-[#151414] overflow-hidden">
        {/* Header */}
        <div className="border-b border-[#2a2828] bg-[#1c1b1b]/90 px-5 py-3.5 flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-4 sm:gap-6 mono text-xs">
            <div className="flex items-center gap-2 text-[#f2f0ef]">
              <span className="text-[#605d5d]">TARGET:</span>
              <span className="font-medium text-white">{SCAN_META.target}</span>
            </div>
            <div className="text-[#9a9695]"><span className="text-[#605d5d]">DATE:</span> {SCAN_META.dateDisplay}</div>
            <div className="text-[#9a9695]"><span className="text-[#605d5d]">TOOL:</span> {SCAN_META.tool}</div>
          </div>
          <button className="mono text-xs text-[#9a9695] hover:text-[#f2f0ef] border border-[#2a2828] px-3 py-1.5 hover:border-[#9a9695] transition-colors flex items-center gap-1.5">
            ↓ Export report
          </button>
        </div>

        {/* Severity bar */}
        <div className="border-b border-[#2a2828] bg-[#0d0c0c] px-5 py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center h-[3px] w-full max-w-xs overflow-hidden gap-px">
            <div className="h-full" style={{ width: `${(counts.high / SAMPLE_TOTAL) * 100}%`, backgroundColor: SEV_COLORS.HIGH.bar }} />
            <div className="h-full" style={{ width: `${(counts.medium / SAMPLE_TOTAL) * 100}%`, backgroundColor: SEV_COLORS.MEDIUM.bar }} />
            <div className="h-full" style={{ width: `${(counts.low / SAMPLE_TOTAL) * 100}%`, backgroundColor: SEV_COLORS.LOW.bar }} />
          </div>
          <div className="mono text-xs tracking-tight">
            <span className="font-medium" style={{ color: SEV_COLORS.HIGH.bar }}>{counts.high} High</span>
            {" · "}
            <span className="font-medium" style={{ color: SEV_COLORS.MEDIUM.bar }}>{counts.medium} Medium</span>
            {" · "}
            <span className="font-medium" style={{ color: SEV_COLORS.LOW.bar }}>{counts.low} Low</span>
          </div>
        </div>

        {/* Split panel */}
        <div className="flex flex-col lg:flex-row min-h-[520px]">
          {/* List */}
          <div className="flex-1 border-r border-[#2a2828] overflow-auto">
            <div className="mono text-[10px] font-medium text-[#605d5d] border-b border-[#2a2828] px-3 py-2 flex gap-3 uppercase">
              <span className="w-[80px] shrink-0">Severity</span>
              <span className="flex-1">Finding</span>
              <span className="w-[80px] shrink-0 hidden sm:block">Path</span>
              <span className="w-[56px] shrink-0 hidden md:block">Module</span>
              <span className="w-[48px] shrink-0 text-right hidden sm:block">Status</span>
            </div>
            {FINDINGS.map((f) => (
              <button
                key={f.id}
                onClick={() => select(f.id)}
                style={{ borderLeftColor: SEV_COLORS[f.severity].bar }}
                className={`w-full text-left border-b border-[#2a2828] border-l-2 px-3 py-2.5 flex items-center gap-3 transition-colors relative mono text-xs ${selectedId === f.id ? "bg-[#1c1b1b]" : "hover:bg-[#1c1b1b]/50"}`}
              >
                {selectedId === f.id && <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-[#22d3a6]" />}
                <div className="w-[80px] shrink-0"><SevPill level={f.severity} /></div>
                <span className="flex-1 font-sans text-sm text-[#f2f0ef] truncate">{f.name}</span>
                <span className="w-[80px] shrink-0 text-[#9a9695] text-[11px] truncate hidden sm:block">{f.path.split(" ")[0]}</span>
                <span className="w-[56px] shrink-0 text-[#605d5d] text-[11px] truncate hidden md:block">{f.module}</span>
                <span className="w-[48px] shrink-0 text-right text-[#9a9695] text-[11px] hidden sm:block">{f.status}</span>
              </button>
            ))}
          </div>

          {/* Detail panel */}
          <div className="w-full lg:w-[420px] shrink-0 flex flex-col overflow-hidden">
            {/* Identity */}
            <div className="px-5 py-4 border-b border-[#2a2828]">
              <div className="flex items-center gap-2 mb-2">
                <SevPill level={sel.severity} />
                <span className="mono text-xs text-[#9a9695] font-medium">{sel.module}</span>
                <span className="mono text-[10px] text-[#3a3836]">·</span>
                <span className={`mono text-[10px] ${sel.status === "New" ? "text-[#22d3a6]" : "text-[#3a3836]"}`}>{sel.status}</span>
              </div>
              <p className="font-bold text-[#f2f0ef] text-base leading-snug mb-1">{sel.name}</p>
              <p className="mono text-xs text-[#605d5d]">{sel.path}</p>
            </div>

            {/* Tabs */}
            <div className="flex border-b border-[#2a2828] px-5">
              {SAMPLE_TABS.map(({ key, label }) => (
                <button
                  key={key}
                  onClick={() => setActiveTab(key)}
                  className={`py-2.5 mr-5 mono text-[11px] tracking-[0.06em] uppercase font-medium border-b-[1.5px] -mb-px transition-colors duration-150 ${activeTab === key ? "border-[#22d3a6] text-[#22d3a6]" : "border-transparent text-[#605d5d] hover:text-[#9a9695]"}`}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div key={`${sel.id}-${activeTab}`} className="flex-1 overflow-y-auto p-5 space-y-4">
              {activeTab === "what" && (
                <p className="text-sm text-[#9a9695] leading-relaxed">{sel.what}</p>
              )}
              {activeTab === "evidence" && (
                <div className="space-y-4">
                  <div>
                    <p className="mono text-[10px] font-medium text-[#605d5d] uppercase tracking-wider mb-2">How to verify</p>
                    <p className="text-sm text-[#9a9695] leading-relaxed mb-3">{sel.howToCheck}</p>
                    <div className="bg-[#0d0c0c] border border-[#2a2828] px-3 py-2.5 mono text-xs text-[#f2f0ef] flex items-start justify-between gap-2">
                      <span className="break-all">{sel.checkCommand}</span>
                      <CopyButton text={sel.checkCommand} className="shrink-0 mt-0.5" />
                    </div>
                  </div>
                  <div>
                    <p className="mono text-[10px] font-medium text-[#605d5d] uppercase tracking-wider mb-2">Scanner evidence</p>
                    <div className="bg-[#0d0c0c] border border-[#2a2828] px-3 py-2.5 mono text-xs text-[#535050] break-all leading-relaxed">
                      {sel.evidence}
                    </div>
                  </div>
                </div>
              )}
              {activeTab === "fix" && (
                <p className="text-sm text-[#9a9695] leading-relaxed whitespace-pre-line">{sel.fix}</p>
              )}
              {activeTab === "refs" && (
                <div className="bg-[#0d0c0c] border border-[#2a2828] px-3 py-2.5 mono text-xs text-[#f2f0ef]">
                  {sel.refs}
                </div>
              )}
            </div>

            <div className="border-t border-[#2a2828] px-5 py-3 flex gap-2">
              <button className="border border-[#2a2828] bg-[#151414] hover:bg-[#1c1b1b] text-[#f2f0ef] text-xs font-semibold px-3 py-1.5 transition-colors">Mark as seen</button>
              <button className="border border-[#2a2828] bg-[#151414] hover:bg-[#1c1b1b] text-[#f2f0ef] text-xs font-semibold px-3 py-1.5 transition-colors">Ignore</button>
            </div>
          </div>
        </div>
      </div>

      <div className="flex flex-wrap gap-6 mt-6 text-sm font-medium text-[#f2f0ef]">
        <button className="flex items-center gap-1.5 hover:text-[#22d3a6] transition-colors" onClick={() => navigator.clipboard?.writeText("webscanx report --format md")}>
          Download sample Markdown →
        </button>
        <button className="flex items-center gap-1.5 hover:text-[#22d3a6] transition-colors" onClick={() => navigator.clipboard?.writeText("webscanx report --format json")}>
          Download sample JSON →
        </button>
      </div>
    </section>
  );
}

function WhatItChecks() {
  const checks = [
    { name: "XSS", desc: "Finds places where your site echoes input back as code a visitor's browser would run.", tags: "reflected · stored · DOM" },
    { name: "Security headers", desc: "Checks the protective headers your server should send with every page.", tags: "CSP · HSTS · X-Frame-Options" },
    { name: "TLS / certificates", desc: "Checks your HTTPS setup for old protocols and expiring certificates.", tags: "TLS 1.0 · ciphers · expiry" },
    { name: "SQL injection", desc: "Finds inputs that can reach your database and change its queries.", tags: "error-based · blind" },
    { name: "CSRF & cookies", desc: "Checks forms for anti-forgery tokens and cookies for safe flags.", tags: "tokens · SameSite · Secure" },
  ];
  return (
    <section id="what-it-checks" className="py-20 sm:py-32 max-w-[1200px] mx-auto px-6">
      <p className="mono text-xs tracking-widest text-[#9a9695] uppercase mb-4">WHAT IT CHECKS</p>
      <h2 className="text-4xl sm:text-[56px] font-bold tracking-tight text-[#f2f0ef] leading-[1.05] mb-10">
        Five checks. Every finding explained.
      </h2>
      <div className="divide-y divide-[#2a2828] border-y border-[#2a2828]">
        {checks.map((c) => (
          <div key={c.name} className="py-7 grid grid-cols-1 md:grid-cols-12 gap-4 items-baseline group hover:bg-[#151414]/60 transition-colors px-4 border-l-2 border-transparent hover:border-[#22d3a6]">
            <div className="md:col-span-4 text-2xl sm:text-[28px] font-bold text-[#f2f0ef] flex items-center gap-2">
              <span>{c.name}</span>
              <span className="text-[#22d3a6] text-sm opacity-0 group-hover:opacity-100 transition-opacity">→</span>
            </div>
            <div className="md:col-span-8 space-y-2">
              <p className="text-base sm:text-lg text-[#9a9695] group-hover:text-[#f2f0ef] transition-colors leading-relaxed">{c.desc}</p>
              <p className="mono text-xs text-[#605d5d]">{c.tags}</p>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function WhyTrustIt() {
  const pillars = [
    { label: "LOCAL-FIRST", title: "Runs on localhost.", body: "No telemetry, no account, works offline." },
    { label: "OPEN-SOURCE", title: "Every check is on GitHub.", body: "Read it, run it, audit it." },
    { label: "SELF-TESTED", title: "We scan WebScanX with WebScanX.", body: "Every release is scanned before we publish it." },
    { label: "AUTHORIZATION-GATED", title: "It won't start until you confirm.", body: "You tick \"I am authorized\" before any scan can start." },
  ];
  return (
    <section className="py-20 sm:py-32 max-w-[1200px] mx-auto px-6">
      <div className="text-center mb-16">
        <p className="mono text-xs tracking-widest text-[#9a9695] uppercase mb-4">WHY TRUST IT</p>
        <h2 className="text-4xl sm:text-[56px] font-bold tracking-tight text-[#f2f0ef] leading-[1.05]">
          Built so you don&apos;t have to trust us.
        </h2>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-20 gap-y-14">
        {pillars.map((p) => (
          <div key={p.label} className="space-y-2">
            <p className="mono text-[11px] font-medium text-[#9a9695] uppercase tracking-wider">{p.label}</p>
            <p className="text-xl font-bold text-[#f2f0ef]">{p.title}</p>
            <p className="text-base text-[#9a9695] leading-relaxed">{p.body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function Download({ platform, setPlatform }: { platform: Platform; setPlatform: (p: Platform) => void }) {
  const platforms: { key: Platform; name: string; meta: string }[] = [
    { key: "win", name: "Windows", meta: ".exe · 24 MB · Windows 10/11" },
    { key: "mac", name: "macOS", meta: ".dmg · 28 MB · Apple Silicon + Intel" },
    { key: "linux", name: "Linux", meta: ".AppImage · 22 MB · x86_64" },
  ];
  return (
    <section id="download" className="py-20 sm:py-32 max-w-[1200px] mx-auto px-6">
      <div className="text-center mb-12">
        <p className="mono text-xs tracking-widest text-[#9a9695] uppercase mb-4">DOWNLOAD</p>
        <h2 className="text-4xl sm:text-[56px] font-bold tracking-tight text-[#f2f0ef]">Download WebScanX v1.0</h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-[#2a2828] border border-[#2a2828] mb-6">
        {platforms.map(({ key, name, meta }) => {
          const d = platformData[key];
          return (
            <div key={key} className="px-7 py-8 space-y-3">
              <p className="text-[28px] font-bold text-[#f2f0ef]">{name}</p>
              <p className="mono text-xs text-[#9a9695]">{meta}</p>
              <button
                onClick={() => setPlatform(key)}
                className="inline-flex items-center justify-center bg-[#22d3a6] text-[#0d0c0c] font-semibold text-sm px-6 py-3 hover:bg-[#20c298] transition-colors w-full sm:w-auto"
              >
                Download {d.exe}
              </button>
              <div className="border-t border-[#2a2828] pt-3 flex items-center justify-between">
                <p className="mono text-[11px] text-[#605d5d]">SHA-256 {d.checksum.slice(0, 16)}…</p>
                <CopyButton text={d.checksum} />
              </div>
            </div>
          );
        })}
      </div>

      <div className="flex flex-col items-center gap-4">
        <div className="bg-[#151414] border border-[#2a2828] px-4 py-2.5 mono text-sm text-[#f2f0ef] flex items-center gap-3">
          <span className="text-[#605d5d]">$</span>
          <span>pip install <span className="font-semibold text-white">webscanx</span></span>
          <CopyButton text="pip install webscanx" />
        </div>
        <div className="flex flex-wrap gap-6 mono text-sm text-[#9a9695]">
          <a href="#" className="hover:text-[#f2f0ef] transition-colors">Release notes</a>
          <a href="#" className="hover:text-[#f2f0ef] transition-colors">Verify signature</a>
          <a href="#" className="hover:text-[#f2f0ef] transition-colors">System requirements</a>
        </div>
      </div>
    </section>
  );
}

function Faq() {
  const questions = [
    { q: "Does anything get uploaded?", a: "No. WebScanX runs entirely on your machine. HTTP requests go directly from your computer to the target. No data passes through WebScanX servers. The only outbound traffic is the scan itself." },
    { q: "Is it legal to scan a website?", a: "You may only scan websites, web services, or staging environments that you own or have explicit written authorization to test. WebScanX enforces an authorization gate before each scan." },
    { q: "Does it fix vulnerabilities?", a: "No. v1 finds and explains each issue and shows you how to fix it yourself. It never changes your site." },
    { q: "What does it need to run?", a: "The standalone binary needs nothing. The pip package requires Python 3.9+. No browser, no Docker, no database." },
    { q: "Is it free?", a: "Yes. WebScanX v1 is free and open source under the MIT license." },
  ];
  return (
    <section id="faq" className="py-20 sm:py-32 max-w-[1200px] mx-auto px-6">
      <h2 className="text-4xl sm:text-[56px] font-bold tracking-tight text-[#f2f0ef] mb-12">Questions</h2>
      <div className="border-t border-[#2a2828]">
        {questions.map((item, i) => (
          <details key={i} className="group border-b border-[#2a2828]">
            <summary className="flex items-center justify-between cursor-pointer list-none py-6 text-xl font-medium text-[#f2f0ef] hover:text-white transition-colors">
              <span>{item.q}</span>
              <span className="mono text-[#9a9695] group-open:hidden">+</span>
              <span className="mono text-[#9a9695] hidden group-open:inline">−</span>
            </summary>
            <div className="pb-6 text-base text-[#9a9695] leading-relaxed max-w-[720px]">
              {item.a}
            </div>
          </details>
        ))}
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="border-t border-[#2a2828] pt-16 pb-0 max-w-[1200px] mx-auto px-6 overflow-hidden">
      <div className="flex flex-wrap gap-8 mb-12">
        <div className="flex-1 min-w-[180px] space-y-2">
          <p className="mono font-medium text-[#f2f0ef] text-lg">WebScanX</p>
          <p className="text-sm text-[#9a9695]">Local web vulnerability scanner.</p>
        </div>
        {[
          { label: "PRODUCT", links: ["Download", "Docs", "Sample report", "Dashboard demo"] },
          { label: "PROJECT", links: ["GitHub", "Security policy", "License"] },
          { label: "LEGAL", links: ["Responsible use", "Privacy"] },
        ].map((col) => (
          <div key={col.label} className="w-[180px] space-y-2">
            <p className="mono text-[11px] font-medium text-[#605d5d]">{col.label}</p>
            {col.links.map((l) => (
              <p key={l} className="text-sm text-[#9a9695] hover:text-[#f2f0ef] cursor-pointer transition-colors">{l}</p>
            ))}
          </div>
        ))}
      </div>
      <div className="border-t border-[#2a2828] py-5">
        <p className="mono text-xs text-[#605d5d]">© 2026 WebScanX · Runs locally.</p>
      </div>
      <p className="font-bold text-[#1c1b1b] text-center leading-none tracking-[-0.05em] select-none" style={{ fontSize: "clamp(60px, 16vw, 220px)" }}>
        WEBSCANX
      </p>
    </footer>
  );
}

export default function ShopPage() {
  const [platform, setPlatform] = useState<Platform>("win");

  return (
    <div className="bg-[#0b0a0a] min-h-screen text-[#f0eeed]">
      <Nav platform={platform} setPlatform={setPlatform} />
      <main className="relative z-10 pt-16">
        <Hero platform={platform} setPlatform={setPlatform} />
        <Statement />
        <HowItWorks />
        <SampleReport />
        <WhatItChecks />
        <WhyTrustIt />
        <Download platform={platform} setPlatform={setPlatform} />
        <Faq />
        <Footer />
      </main>
    </div>
  );
}
