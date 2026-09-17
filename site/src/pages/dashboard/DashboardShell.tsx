import { useState, useEffect, type ReactNode } from "react";

type Screen = "new-scan" | "results" | "history" | "settings";

function navigate(screen: Screen) {
  window.location.hash = `/dashboard/${screen}`;
}

function useCurrentScreen(): Screen {
  const getScreen = (): Screen => {
    const h = window.location.hash;
    if (h.includes("results")) return "results";
    if (h.includes("history")) return "history";
    if (h.includes("settings")) return "settings";
    return "new-scan";
  };
  const [screen, setScreen] = useState<Screen>(getScreen);
  useEffect(() => {
    const fn = () => setScreen(getScreen());
    window.addEventListener("hashchange", fn);
    return () => window.removeEventListener("hashchange", fn);
  }, []);
  return screen;
}

const NAV: { id: Screen; label: string; icon: ReactNode }[] = [
  {
    id: "new-scan",
    label: "New Scan",
    icon: (
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="7" cy="7" r="2.5" />
        <path d="M7 1v1.5M7 11.5V13M1 7h1.5M11.5 7H13" />
        <path d="M3.05 3.05l1.06 1.06M9.89 9.89l1.06 1.06M10.95 3.05L9.89 4.11M4.11 9.89l-1.06 1.06" opacity="0.5"/>
      </svg>
    ),
  },
  {
    id: "results",
    label: "Results",
    icon: (
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
        <rect x="1.5" y="1.5" width="11" height="11" rx="1" />
        <path d="M4 5h6M4 7.5h4M4 10h2" />
      </svg>
    ),
  },
  {
    id: "history",
    label: "History",
    icon: (
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="7" cy="7" r="5.5" />
        <path d="M7 4.5V7l1.75 1.75" />
      </svg>
    ),
  },
  {
    id: "settings",
    label: "Settings",
    icon: (
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="7" cy="7" r="2" />
        <path d="M7 1.5v1M7 11.5v1M1.5 7h1M11.5 7h1M3.11 3.11l.71.71M10.18 10.18l.71.71M10.89 3.11l-.71.71M3.82 10.18l-.71.71" />
      </svg>
    ),
  },
];

export default function DashboardShell({ children }: { children: ReactNode }) {
  const screen = useCurrentScreen();

  return (
    <div className="flex h-screen bg-[#0b0a0a] text-[#f0eeed] overflow-hidden">
      {/* ── Sidebar ── */}
      <aside className="w-[200px] shrink-0 flex flex-col bg-[#0b0a0a] border-r border-[#1e1c1c]">

        {/* Brand */}
        <div className="px-5 pt-5 pb-4 border-b border-[#1e1c1c]">
          <div className="flex items-baseline gap-2">
            <span className="font-semibold text-[14px] tracking-[-0.02em] text-[#f0eeed]">WebScanX</span>
            <span className="mono text-[9px] text-[#535050] tracking-[0.06em] uppercase">v1.0</span>
          </div>
          <div className="flex items-center gap-1.5 mt-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#22d3a6] live-pulse" />
            <span className="mono text-[10px] text-[#535050] tracking-[0.04em]">localhost:8080</span>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-2">
          <div className="px-3 py-2 label-caps text-[#3a3836] mb-1">Scan</div>
          {NAV.map(({ id, label, icon }) => {
            const active = screen === id;
            return (
              <button
                key={id}
                onClick={() => navigate(id)}
                className={`
                  w-full flex items-center gap-2.5 px-3 py-2 text-[13px] font-medium
                  transition-colors duration-150 relative
                  ${active
                    ? "text-[#f0eeed] bg-[#151414]"
                    : "text-[#535050] hover:text-[#8a8785] hover:bg-[#111010]"
                  }
                `}
              >
                {active && (
                  <span className="absolute left-0 top-1.5 bottom-1.5 w-[2px] bg-[#22d3a6]" />
                )}
                <span className={active ? "text-[#22d3a6]" : ""}>{icon}</span>
                {label}
              </button>
            );
          })}
        </nav>

        {/* Bottom dock */}
        <div className="border-t border-[#1e1c1c] px-4 py-4 space-y-3">
          <div className="flex items-center gap-1.5">
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="#22d3a6" strokeWidth="1.2" strokeLinecap="round">
              <path d="M5 1v4l2 2" /><circle cx="5" cy="5" r="4" />
            </svg>
            <span className="mono text-[10px] text-[#535050]">Offline-safe</span>
          </div>
          <p className="mono text-[10px] text-[#3a3836] leading-relaxed">
            No data leaves this device
          </p>
          <button
            onClick={() => { window.location.hash = ""; }}
            className="mono text-[10px] text-[#3a3836] hover:text-[#535050] transition-colors duration-150 flex items-center gap-1"
          >
            ← shop
          </button>
        </div>
      </aside>

      {/* ── Main ── */}
      <main className="flex-1 flex flex-col overflow-hidden min-w-0">
        {children}
      </main>
    </div>
  );
}
