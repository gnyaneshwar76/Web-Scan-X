type ButtonProps = {
  className?: string;
  label?: string;
  type?: "Primary" | "Secondary";
};

function Button({ className, label = "Button", type = "Primary" }: ButtonProps) {
  const isSecondary = type === "Secondary";
  return (
    <div className={className || `h-[36px] relative ${isSecondary ? "bg-[#151414]" : "bg-[#22d3a6]"}`}>
      <div aria-hidden={isSecondary ? true : undefined} className={isSecondary ? "absolute border border-[#2a2828] border-solid inset-0 pointer-events-none" : "flex flex-row items-center justify-center size-full"}>
        {type === "Primary" && (
          <div className="content-stretch flex items-center justify-center px-[14px] relative size-full">
            <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#0d0c0c] text-[13px] whitespace-nowrap">{label}</p>
          </div>
        )}
      </div>
      {isSecondary && (
        <div className="flex flex-row items-center justify-center size-full">
          <div className="content-stretch flex items-center justify-center px-[14px] relative size-full">
            <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#f2f0ef] text-[13px] whitespace-nowrap">{label}</p>
          </div>
        </div>
      )}
    </div>
  );
}
type SeverityPillProps = {
  className?: string;
  severity?: "high" | "medium" | "low" | "info";
};

function SeverityPill({ className, severity = "high" }: SeverityPillProps) {
  const isInfo = severity === "info";
  const isLow = severity === "low";
  const isMedium = severity === "medium";
  return (
    <div className={className || "relative rounded-[2px]"}>
      <div className="content-stretch flex items-start px-[6px] py-[4px] relative size-full">
        <div className={`absolute inset-0 opacity-12 ${isInfo ? "bg-[#8a8a8a]" : isLow ? "bg-[#eab308]" : isMedium ? "bg-[#f97316]" : "bg-[#ef4444]"}`} data-name="tint" />
        <p className={`[word-break:break-word] font-["JetBrains_Mono:Bold",sans-serif] font-bold leading-[normal] relative shrink-0 text-[10px] whitespace-nowrap ${isInfo ? "text-[#8a8a8a]" : isLow ? "text-[#eab308]" : isMedium ? "text-[#f97316]" : "text-[#ef4444]"}`}>{isInfo ? "INFO" : isLow ? "LOW" : isMedium ? "MEDIUM" : "HIGH"}</p>
      </div>
    </div>
  );
}
type FindingRowProps = {
  className?: string;
  finding?: string;
  location?: string;
  module?: string;
  state?: "Default" | "Selected";
  status?: string;
};

function FindingRow({ className, finding = "Reflected XSS in ?q parameter", location = "/search?q=", module = "XSS", state = "Default", status = "New" }: FindingRowProps) {
  const isSelected = state === "Selected";
  return (
    <div className={className || `h-[42px] relative w-[680px] ${isSelected ? "bg-[#1c1b1b]" : ""}`}>
      <div aria-hidden className="absolute border-[#2a2828] border-b border-solid inset-0 pointer-events-none" />
      <div className="flex flex-row items-center size-full">
        <div className="content-stretch flex gap-[12px] items-center px-[12px] relative size-full">
          <div className="content-stretch flex h-[20px] items-start overflow-clip relative shrink-0 w-[80px]" data-name="Severity">
            <SeverityPill className="relative rounded-[2px] shrink-0" />
          </div>
          <p className="[word-break:break-word] flex-[1_0_0] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] min-w-px overflow-hidden relative text-[#f2f0ef] text-[14px] text-ellipsis whitespace-nowrap">{finding}</p>
          <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis w-[120px] whitespace-nowrap">{location}</p>
          <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#605d5d] text-[11px] text-ellipsis w-[64px] whitespace-nowrap">{module}</p>
          <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis text-right w-[56px] whitespace-nowrap">{status}</p>
          {isSelected && <div className="absolute bg-[#22d3a6] h-[42px] left-0 top-0 w-[2px]" data-name="selected-bar" />}
        </div>
      </div>
    </div>
  );
}

function Report({ className }: { className?: string }) {
  return (
    <div className={className || "bg-[#151414] h-[760px] relative w-[1136px]"} data-name="Report">
      <div className="overflow-clip rounded-[inherit] size-full">
        <div className="content-stretch flex flex-col items-start relative size-full">
          <div className="border-[#2a2828] border-b border-solid content-stretch flex gap-[16px] items-center overflow-clip px-[16px] py-[12px] relative shrink-0 w-full" data-name="Header">
            <p className="[word-break:break-word] font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#f2f0ef] text-[12px] whitespace-nowrap">{`https://demo.webscanx.internal`}</p>
            <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] whitespace-nowrap">14 Sep 2026, 14:02</p>
            <p className="[word-break:break-word] flex-[1_0_0] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] min-w-px relative text-[#9a9695] text-[12px]">3m 42s</p>
            <Button className="bg-[#151414] h-[36px] relative shrink-0" label="Export report" type="Secondary" />
          </div>
          <div className="border-[#2a2828] border-b border-solid content-stretch flex flex-col gap-[8px] items-start overflow-clip px-[16px] py-[12px] relative shrink-0 w-full" data-name="Severity summary">
            <div className="h-[6px] overflow-clip relative shrink-0 w-full" data-name="Stacked bar">
              <div className="absolute bg-[#ef4444] inset-[0_88.93%_0_0]" data-name="high 2" />
              <div className="absolute bg-[#f97316] inset-[0_72.14%_0_11.25%]" data-name="medium 3" />
              <div className="absolute bg-[#eab308] inset-[0_44.37%_0_28.04%]" data-name="low 5" />
              <div className="absolute bg-[#8a8a8a] inset-[0_0_0_55.81%]" data-name="info 8" />
            </div>
            <div className="[word-break:break-word] content-stretch flex font-['JetBrains_Mono:Regular',sans-serif] font-normal gap-[14px] items-start leading-[normal] overflow-clip relative shrink-0 text-[12px] whitespace-nowrap" data-name="Legend">
              <p className="relative shrink-0 text-[#ef4444]">2 High</p>
              <p className="relative shrink-0 text-[#f97316]">3 Medium</p>
              <p className="relative shrink-0 text-[#eab308]">5 Low</p>
              <p className="relative shrink-0 text-[#8a8a8a]">8 Info</p>
            </div>
          </div>
          <div className="border-[#2a2828] border-b border-solid content-stretch flex gap-[2px] items-center overflow-clip px-[16px] py-[8px] relative shrink-0 w-full" data-name="Filters">
            <div className="bg-[#1c1b1b] border border-[#2a2828] border-solid content-stretch flex items-start overflow-clip px-[10px] py-[5px] relative shrink-0" data-name="Tab All (18)">
              <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#f2f0ef] text-[12px] whitespace-nowrap">All (18)</p>
            </div>
            <div className="content-stretch flex items-start overflow-clip px-[10px] py-[5px] relative shrink-0" data-name="Tab Critical (0)">
              <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#605d5d] text-[12px] whitespace-nowrap">Critical (0)</p>
            </div>
            <div className="content-stretch flex items-start overflow-clip px-[10px] py-[5px] relative shrink-0" data-name="Tab High (2)">
              <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] whitespace-nowrap">High (2)</p>
            </div>
            <div className="content-stretch flex items-start overflow-clip px-[10px] py-[5px] relative shrink-0" data-name="Tab Medium (3)">
              <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] whitespace-nowrap">Medium (3)</p>
            </div>
            <div className="content-stretch flex items-start overflow-clip px-[10px] py-[5px] relative shrink-0" data-name="Tab Low (5)">
              <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] whitespace-nowrap">Low (5)</p>
            </div>
            <div className="content-stretch flex items-start overflow-clip px-[10px] py-[5px] relative shrink-0" data-name="Tab Info (8)">
              <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] whitespace-nowrap">Info (8)</p>
            </div>
            <div className="flex-[1_0_0] h-px min-w-px relative" data-name="spacer" />
            <div className="bg-[#0d0c0c] border border-[#2a2828] border-solid content-stretch flex h-[32px] items-center overflow-clip pl-[10px] relative shrink-0 w-[180px]" data-name="Search findings">
              <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#605d5d] text-[12px] whitespace-nowrap">Search findings</p>
            </div>
            <div className="bg-[#0d0c0c] border border-[#2a2828] border-solid content-stretch flex h-[32px] items-center overflow-clip pl-[10px] relative shrink-0 w-[140px]" data-name="Module: All">
              <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#f2f0ef] text-[12px] whitespace-nowrap">Module: All</p>
            </div>
          </div>
          <div className="content-stretch flex flex-[1_0_0] items-start min-h-px overflow-clip relative w-full" data-name="Body">
            <div className="border-[#2a2828] border-r border-solid content-stretch flex flex-[1_0_0] flex-col h-full items-start min-w-px overflow-clip relative" data-name="Findings list">
              <div className="[word-break:break-word] border-[#2a2828] border-b border-solid content-stretch flex font-['JetBrains_Mono:Medium',sans-serif] font-medium gap-[12px] h-[34px] items-center leading-[normal] overflow-clip px-[12px] relative shrink-0 text-[#605d5d] text-[10px] w-full" data-name="Table header">
                <p className="relative shrink-0 w-[80px]">SEVERITY</p>
                <p className="flex-[1_0_0] min-w-px relative">FINDING</p>
                <p className="relative shrink-0 w-[120px]">LOCATION</p>
                <p className="relative shrink-0 w-[64px]">MODULE</p>
                <p className="relative shrink-0 text-right w-[56px]">STATUS</p>
              </div>
              <FindingRow className="bg-[#1c1b1b] h-[42px] relative shrink-0 w-full" state="Selected" />
              <FindingRow className="h-[42px] relative shrink-0 w-full" finding="Missing Content-Security-Policy header" location="/" module="HEADERS" />
              <div className="h-[42px] relative shrink-0 w-full" data-name="TLS 1.0 enabled">
                <div aria-hidden className="absolute border-[#2a2828] border-b border-solid inset-0 pointer-events-none" />
                <div className="flex flex-row items-center size-full">
                  <div className="content-stretch flex gap-[12px] items-center px-[12px] relative size-full">
                    <div className="content-stretch flex h-[20px] items-start overflow-clip relative shrink-0 w-[80px]" data-name="Severity">
                      <div className="relative rounded-[2px] shrink-0" data-name="Pill">
                        <div className="content-stretch flex items-start px-[6px] py-[4px] relative size-full">
                          <div className="absolute bg-[#f97316] inset-0 opacity-12" data-name="tint" />
                          <p className="[word-break:break-word] font-['JetBrains_Mono:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#f97316] text-[10px] whitespace-nowrap">MEDIUM</p>
                        </div>
                      </div>
                    </div>
                    <p className="[word-break:break-word] flex-[1_0_0] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] min-w-px overflow-hidden relative text-[#f2f0ef] text-[14px] text-ellipsis whitespace-nowrap">TLS 1.0 enabled</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis w-[120px] whitespace-nowrap">:443</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#605d5d] text-[11px] text-ellipsis w-[64px] whitespace-nowrap">TLS</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis text-right w-[56px] whitespace-nowrap">Seen</p>
                  </div>
                </div>
              </div>
              <div className="h-[42px] relative shrink-0 w-full" data-name="Cookie without Secure flag">
                <div aria-hidden className="absolute border-[#2a2828] border-b border-solid inset-0 pointer-events-none" />
                <div className="flex flex-row items-center size-full">
                  <div className="content-stretch flex gap-[12px] items-center px-[12px] relative size-full">
                    <div className="content-stretch flex h-[20px] items-start overflow-clip relative shrink-0 w-[80px]" data-name="Severity">
                      <div className="relative rounded-[2px] shrink-0" data-name="Pill">
                        <div className="content-stretch flex items-start px-[6px] py-[4px] relative size-full">
                          <div className="absolute bg-[#f97316] inset-0 opacity-12" data-name="tint" />
                          <p className="[word-break:break-word] font-['JetBrains_Mono:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#f97316] text-[10px] whitespace-nowrap">MEDIUM</p>
                        </div>
                      </div>
                    </div>
                    <p className="[word-break:break-word] flex-[1_0_0] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] min-w-px overflow-hidden relative text-[#f2f0ef] text-[14px] text-ellipsis whitespace-nowrap">Cookie without Secure flag</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis w-[120px] whitespace-nowrap">/login</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#605d5d] text-[11px] text-ellipsis w-[64px] whitespace-nowrap">CSRF</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis text-right w-[56px] whitespace-nowrap">New</p>
                  </div>
                </div>
              </div>
              <div className="h-[42px] relative shrink-0 w-full" data-name="SQL error message disclosed">
                <div aria-hidden className="absolute border-[#2a2828] border-b border-solid inset-0 pointer-events-none" />
                <div className="flex flex-row items-center size-full">
                  <div className="content-stretch flex gap-[12px] items-center px-[12px] relative size-full">
                    <div className="content-stretch flex h-[20px] items-start overflow-clip relative shrink-0 w-[80px]" data-name="Severity">
                      <div className="relative rounded-[2px] shrink-0" data-name="Pill">
                        <div className="content-stretch flex items-start px-[6px] py-[4px] relative size-full">
                          <div className="absolute bg-[#f97316] inset-0 opacity-12" data-name="tint" />
                          <p className="[word-break:break-word] font-['JetBrains_Mono:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#f97316] text-[10px] whitespace-nowrap">MEDIUM</p>
                        </div>
                      </div>
                    </div>
                    <p className="[word-break:break-word] flex-[1_0_0] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] min-w-px overflow-hidden relative text-[#f2f0ef] text-[14px] text-ellipsis whitespace-nowrap">SQL error message disclosed</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis w-[120px] whitespace-nowrap">/api/items</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#605d5d] text-[11px] text-ellipsis w-[64px] whitespace-nowrap">SQLI</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis text-right w-[56px] whitespace-nowrap">New</p>
                  </div>
                </div>
              </div>
              <div className="h-[42px] relative shrink-0 w-full" data-name="Missing X-Content-Type-Options header">
                <div aria-hidden className="absolute border-[#2a2828] border-b border-solid inset-0 pointer-events-none" />
                <div className="flex flex-row items-center size-full">
                  <div className="content-stretch flex gap-[12px] items-center px-[12px] relative size-full">
                    <div className="content-stretch flex h-[20px] items-start overflow-clip relative shrink-0 w-[80px]" data-name="Severity">
                      <div className="relative rounded-[2px] shrink-0" data-name="Pill">
                        <div className="content-stretch flex items-start px-[6px] py-[4px] relative size-full">
                          <div className="absolute bg-[#eab308] inset-0 opacity-12" data-name="tint" />
                          <p className="[word-break:break-word] font-['JetBrains_Mono:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#eab308] text-[10px] whitespace-nowrap">LOW</p>
                        </div>
                      </div>
                    </div>
                    <p className="[word-break:break-word] flex-[1_0_0] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] min-w-px overflow-hidden relative text-[#f2f0ef] text-[14px] text-ellipsis whitespace-nowrap">Missing X-Content-Type-Options header</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis w-[120px] whitespace-nowrap">/</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#605d5d] text-[11px] text-ellipsis w-[64px] whitespace-nowrap">HEADERS</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis text-right w-[56px] whitespace-nowrap">Seen</p>
                  </div>
                </div>
              </div>
              <div className="h-[42px] relative shrink-0 w-full" data-name="Missing CSRF token on /account/email">
                <div aria-hidden className="absolute border-[#2a2828] border-b border-solid inset-0 pointer-events-none" />
                <div className="flex flex-row items-center size-full">
                  <div className="content-stretch flex gap-[12px] items-center px-[12px] relative size-full">
                    <div className="content-stretch flex h-[20px] items-start overflow-clip relative shrink-0 w-[80px]" data-name="Severity">
                      <div className="relative rounded-[2px] shrink-0" data-name="Pill">
                        <div className="content-stretch flex items-start px-[6px] py-[4px] relative size-full">
                          <div className="absolute bg-[#eab308] inset-0 opacity-12" data-name="tint" />
                          <p className="[word-break:break-word] font-['JetBrains_Mono:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#eab308] text-[10px] whitespace-nowrap">LOW</p>
                        </div>
                      </div>
                    </div>
                    <p className="[word-break:break-word] flex-[1_0_0] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] min-w-px overflow-hidden relative text-[#f2f0ef] text-[14px] text-ellipsis whitespace-nowrap">Missing CSRF token on /account/email</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis w-[120px] whitespace-nowrap">/account/email</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#605d5d] text-[11px] text-ellipsis w-[64px] whitespace-nowrap">CSRF</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis text-right w-[56px] whitespace-nowrap">New</p>
                  </div>
                </div>
              </div>
              <div className="h-[42px] opacity-50 relative shrink-0 w-full" data-name="Clickjacking protection missing">
                <div aria-hidden className="absolute border-[#2a2828] border-b border-solid inset-0 pointer-events-none" />
                <div className="flex flex-row items-center size-full">
                  <div className="content-stretch flex gap-[12px] items-center px-[12px] relative size-full">
                    <div className="content-stretch flex h-[20px] items-start overflow-clip relative shrink-0 w-[80px]" data-name="Severity">
                      <div className="relative rounded-[2px] shrink-0" data-name="Pill">
                        <div className="content-stretch flex items-start px-[6px] py-[4px] relative size-full">
                          <div className="absolute bg-[#eab308] inset-0 opacity-12" data-name="tint" />
                          <p className="[word-break:break-word] font-['JetBrains_Mono:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#eab308] text-[10px] whitespace-nowrap">LOW</p>
                        </div>
                      </div>
                    </div>
                    <p className="[word-break:break-word] flex-[1_0_0] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] min-w-px overflow-hidden relative text-[#f2f0ef] text-[14px] text-ellipsis whitespace-nowrap">Clickjacking protection missing</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis w-[120px] whitespace-nowrap">/</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#605d5d] text-[11px] text-ellipsis w-[64px] whitespace-nowrap">HEADERS</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis text-right w-[56px] whitespace-nowrap">Ignored</p>
                  </div>
                </div>
              </div>
              <div className="h-[42px] relative shrink-0 w-full" data-name="Missing Strict-Transport-Security header">
                <div aria-hidden className="absolute border-[#2a2828] border-b border-solid inset-0 pointer-events-none" />
                <div className="flex flex-row items-center size-full">
                  <div className="content-stretch flex gap-[12px] items-center px-[12px] relative size-full">
                    <div className="content-stretch flex h-[20px] items-start overflow-clip relative shrink-0 w-[80px]" data-name="Severity">
                      <div className="relative rounded-[2px] shrink-0" data-name="Pill">
                        <div className="content-stretch flex items-start px-[6px] py-[4px] relative size-full">
                          <div className="absolute bg-[#eab308] inset-0 opacity-12" data-name="tint" />
                          <p className="[word-break:break-word] font-['JetBrains_Mono:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#eab308] text-[10px] whitespace-nowrap">LOW</p>
                        </div>
                      </div>
                    </div>
                    <p className="[word-break:break-word] flex-[1_0_0] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] min-w-px overflow-hidden relative text-[#f2f0ef] text-[14px] text-ellipsis whitespace-nowrap">Missing Strict-Transport-Security header</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis w-[120px] whitespace-nowrap">/</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#605d5d] text-[11px] text-ellipsis w-[64px] whitespace-nowrap">HEADERS</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis text-right w-[56px] whitespace-nowrap">New</p>
                  </div>
                </div>
              </div>
              <div className="h-[42px] relative shrink-0 w-full" data-name="Server header shows version (nginx/1.18.0)">
                <div aria-hidden className="absolute border-[#2a2828] border-b border-solid inset-0 pointer-events-none" />
                <div className="flex flex-row items-center size-full">
                  <div className="content-stretch flex gap-[12px] items-center px-[12px] relative size-full">
                    <div className="content-stretch flex h-[20px] items-start overflow-clip relative shrink-0 w-[80px]" data-name="Severity">
                      <div className="relative rounded-[2px] shrink-0" data-name="Pill">
                        <div className="content-stretch flex items-start px-[6px] py-[4px] relative size-full">
                          <div className="absolute bg-[#8a8a8a] inset-0 opacity-12" data-name="tint" />
                          <p className="[word-break:break-word] font-['JetBrains_Mono:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#8a8a8a] text-[10px] whitespace-nowrap">INFO</p>
                        </div>
                      </div>
                    </div>
                    <p className="[word-break:break-word] flex-[1_0_0] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] min-w-px overflow-hidden relative text-[#f2f0ef] text-[14px] text-ellipsis whitespace-nowrap">Server header shows version (nginx/1.18.0)</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis w-[120px] whitespace-nowrap">/</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#605d5d] text-[11px] text-ellipsis w-[64px] whitespace-nowrap">HEADERS</p>
                    <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] overflow-hidden relative shrink-0 text-[#9a9695] text-[12px] text-ellipsis text-right w-[56px] whitespace-nowrap">Seen</p>
                  </div>
                </div>
              </div>
              <div className="content-stretch flex items-start overflow-clip pl-[16px] py-[12px] relative shrink-0" data-name="More">
                <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#605d5d] text-[11px] whitespace-nowrap">+ 8 more findings</p>
              </div>
            </div>
            <div className="content-stretch flex flex-col gap-[20px] h-full items-start overflow-clip p-[20px] relative shrink-0 w-[440px]" data-name="Detail panel">
              <div className="content-stretch flex gap-[8px] items-center overflow-clip relative shrink-0" data-name="Tags">
                <SeverityPill className="relative rounded-[2px] shrink-0" />
                <p className="[word-break:break-word] font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#9a9695] text-[11px] whitespace-nowrap">XSS</p>
              </div>
              <div className="[word-break:break-word] content-stretch flex flex-col gap-[4px] items-start leading-[normal] overflow-clip relative shrink-0 w-full" data-name="Title">
                <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold relative shrink-0 text-[#f2f0ef] text-[18px] w-full">Reflected XSS in ?q parameter</p>
                <p className="font-['JetBrains_Mono:Regular',sans-serif] font-normal relative shrink-0 text-[#9a9695] text-[12px] w-full">demo.webscanx.internal/search?q=</p>
              </div>
              <div className="[word-break:break-word] content-stretch flex flex-col gap-[8px] items-start leading-[normal] overflow-clip relative shrink-0 text-[#9a9695] w-full" data-name="What it is">
                <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium relative shrink-0 text-[11px] whitespace-nowrap">WHAT IT IS</p>
                <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal min-w-full relative shrink-0 text-[14px] w-[min-content]">{`The search box sends your text back into the page without cleaning it. An attacker can make a link that runs their own script in a visitor's browser.`}</p>
              </div>
              <div className="content-stretch flex flex-col gap-[8px] items-start overflow-clip relative shrink-0 w-full" data-name="How to check it yourself">
                <p className="[word-break:break-word] font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#9a9695] text-[11px] whitespace-nowrap">HOW TO CHECK IT YOURSELF</p>
                <div className="[word-break:break-word] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[0] min-w-full relative shrink-0 text-[#9a9695] text-[14px] w-[min-content]">
                  <p className="leading-[normal] mb-0">1. Run the command below.</p>
                  <p className="leading-[normal]">2. If the script tag comes back unchanged in the response, the issue is real.</p>
                </div>
                <div className="bg-[#0d0c0c] border border-[#2a2828] border-solid content-stretch flex flex-col items-start overflow-clip px-[12px] py-[10px] relative shrink-0 w-full" data-name="Code block">
                  <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[19px] relative shrink-0 text-[#f2f0ef] text-[12px] w-full">{`curl -s "https://demo.webscanx.internal/search?q=%3Cscript%3Ealert(1)%3C/script%3E"`}</p>
                </div>
              </div>
              <div className="content-stretch flex flex-col gap-[8px] items-start overflow-clip relative shrink-0 w-full" data-name="Evidence">
                <p className="[word-break:break-word] font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#9a9695] text-[11px] whitespace-nowrap">EVIDENCE</p>
                <div className="bg-[#0d0c0c] border border-[#2a2828] border-solid content-stretch flex flex-col items-start overflow-clip px-[12px] py-[10px] relative shrink-0 w-full" data-name="Code block">
                  <div className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[0] relative shrink-0 text-[#f2f0ef] text-[12px] w-full whitespace-pre-wrap">
                    <p className="leading-[19px] mb-0">HTTP/1.1 200 OK</p>
                    <p className="leading-[19px] mb-0">​</p>
                    <p className="leading-[19px] mb-0">{`<div class="query-echo">`}</p>
                    <p className="mb-0">
                      <span className="leading-[19px]">{`  Results for: `}</span>
                      <span className="[word-break:break-word] font-['JetBrains_Mono:Bold',sans-serif] font-bold leading-[19px] text-[#ef4444]">{`<script>alert(1)</script>`}</span>
                    </p>
                    <p className="leading-[19px]">{`</div>`}</p>
                  </div>
                </div>
              </div>
              <div className="[word-break:break-word] content-stretch flex flex-col gap-[8px] items-start overflow-clip relative shrink-0 text-[#9a9695] w-full" data-name="How to fix it">
                <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[11px] whitespace-nowrap">HOW TO FIX IT</p>
                <div className="font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[0] min-w-full relative shrink-0 text-[14px] w-[min-content]">
                  <p className="leading-[normal] mb-0">• Encode user input before putting it into HTML.</p>
                  <p className="leading-[normal]">• Add a Content-Security-Policy header that blocks inline scripts.</p>
                </div>
              </div>
              <div className="[word-break:break-word] content-stretch flex flex-col gap-[8px] items-start leading-[normal] overflow-clip relative shrink-0 w-full" data-name="References">
                <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium relative shrink-0 text-[#9a9695] text-[11px] whitespace-nowrap">REFERENCES</p>
                <p className="font-['JetBrains_Mono:Regular',sans-serif] font-normal min-w-full relative shrink-0 text-[#f2f0ef] text-[12px] w-[min-content]">OWASP A03 · CWE-79</p>
              </div>
              <div className="border-[#2a2828] border-solid border-t content-stretch flex gap-[8px] items-start overflow-clip pt-[16px] relative shrink-0 w-full" data-name="Actions">
                <Button className="bg-[#151414] h-[36px] relative shrink-0" label="Mark as seen" type="Secondary" />
                <Button className="bg-[#151414] h-[36px] relative shrink-0" label="Ignore" type="Secondary" />
              </div>
            </div>
          </div>
        </div>
      </div>
      <div aria-hidden className="absolute border border-[#2a2828] border-solid inset-0 pointer-events-none" />
    </div>
  );
}

function Links() {
  return (
    <div className="[word-break:break-word] content-stretch flex font-['Space_Grotesk:Regular',sans-serif] font-normal gap-[28px] items-start leading-[normal] overflow-clip relative shrink-0 text-[#9a9695] text-[14px] whitespace-nowrap" data-name="Links">
      <p className="relative shrink-0">How it works</p>
      <p className="relative shrink-0">Sample report</p>
      <p className="relative shrink-0">What it checks</p>
      <p className="relative shrink-0">Docs</p>
      <p className="relative shrink-0">GitHub</p>
    </div>
  );
}

function Nav() {
  return (
    <div className="border-[#2a2828] border-b border-solid content-stretch flex h-[64px] items-center justify-between overflow-clip px-[120px] relative shrink-0 w-full" data-name="Nav">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#f2f0ef] text-[17px] whitespace-nowrap">WebScanX</p>
      <Links />
      <Button className="bg-[#22d3a6] h-[36px] relative shrink-0" label="Download" />
    </div>
  );
}

function Cta() {
  return (
    <div className="content-stretch flex gap-[20px] items-center overflow-clip relative shrink-0" data-name="CTA">
      <Button className="bg-[#22d3a6] h-[48px] relative shrink-0" label="Download for Windows" />
      <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#605d5d] text-[12px] whitespace-nowrap">v1.0 · 24 MB</p>
      <p className="[word-break:break-word] font-['Space_Grotesk:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#f2f0ef] text-[14px] whitespace-nowrap">Try the dashboard →</p>
    </div>
  );
}

function ProductPreviewTilt18FadeInCode() {
  return (
    <div className="h-[540px] overflow-clip relative shrink-0 w-[1160px]" data-name="Product preview (tilt 18° + fade in code)">
      <Report className="absolute bg-[#151414] h-[760px] left-0 top-[40px] w-[1160px]" />
      <div className="absolute bg-gradient-to-b from-1/2 from-[rgba(13,12,12,0)] h-[540px] left-0 to-[#0d0c0c] top-0 w-[1160px]" data-name="Bottom fade" />
    </div>
  );
}

function Hero() {
  return (
    <div className="content-stretch flex flex-col gap-[28px] items-center overflow-clip pt-[112px] relative shrink-0 w-full" style={{ backgroundImage: "url(\"data:image/svg+xml;utf8,<svg viewBox='0 0 1440 1066' xmlns='http://www.w3.org/2000/svg' preserveAspectRatio='none'><rect x='0' y='0' height='100%' width='100%' fill='url(%23grad)' opacity='1'/><defs><radialGradient id='grad' gradientUnits='userSpaceOnUse' cx='0' cy='0' r='10' gradientTransform='matrix(120 0 0 106.6 720 1066)'><stop stop-color='rgba(34,211,166,0.09)' offset='0'/><stop stop-color='rgba(13,12,12,0)' offset='1'/></radialGradient></defs></svg>\")" }} data-name="Hero">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] tracking-[1.68px] whitespace-nowrap">OPEN-SOURCE · RUNS 100% LOCALLY</p>
      <div className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[0] relative shrink-0 text-[#f2f0ef] text-[96px] text-center tracking-[-4.32px] whitespace-nowrap">
        <p className="leading-[96px] mb-0">Find your vulnerabilities</p>
        <p className="leading-[96px] text-[#9a9695]">before they do.</p>
      </div>
      <p className="[word-break:break-word] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#9a9695] text-[18px] text-center w-[580px]">A local scanner that finds web vulnerabilities and explains each one in plain language. Nothing leaves your device.</p>
      <Cta />
      <ProductPreviewTilt18FadeInCode />
    </div>
  );
}

function MarqueeAnimated() {
  return (
    <div className="content-stretch flex font-['JetBrains_Mono:Regular',sans-serif] font-normal gap-[56px] items-start leading-[normal] overflow-clip relative shrink-0 text-[#605d5d] text-[13px] tracking-[1.82px] whitespace-nowrap" data-name="Marquee (animated)">
      <p className="relative shrink-0">SECURITY HEADERS</p>
      <p className="relative shrink-0">TLS</p>
      <p className="relative shrink-0">XSS</p>
      <p className="relative shrink-0">SQL INJECTION</p>
      <p className="relative shrink-0">CSRF</p>
      <p className="relative shrink-0">COOKIES</p>
      <p className="relative shrink-0">CORS</p>
      <p className="relative shrink-0">CSP</p>
      <p className="relative shrink-0">OPEN REDIRECTS</p>
    </div>
  );
}

function Statement() {
  return (
    <div className="[word-break:break-word] content-stretch flex flex-col gap-[64px] items-center overflow-clip pt-[96px] px-[120px] relative shrink-0 w-full" data-name="Statement">
      <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[0] relative shrink-0 text-[#f2f0ef] text-[44px] text-center tracking-[-0.88px] w-[920px]">
        <span className="leading-[1.2]">{`WebScanX finds web vulnerabilities, `}</span>
        <span className="leading-[1.2] text-[#605d5d]">explains them</span>
        <span className="leading-[1.2]">{` like a colleague would, `}</span>
        <span className="leading-[1.2] text-[#605d5d]">and</span>
        <span className="leading-[1.2]">{` never sends a byte off your machine.`}</span>
      </p>
      <MarqueeAnimated />
    </div>
  );
}

function Fragment() {
  return (
    <div className="bg-[#151414] border border-[#2a2828] border-solid content-stretch flex flex-col items-start overflow-clip p-[14px] relative shrink-0 w-full" data-name="Fragment">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#f2f0ef] text-[13px] whitespace-nowrap">$ webscanx start</p>
    </div>
  );
}

function Step() {
  return (
    <div className="border-[#2a2828] border-solid border-t content-stretch flex flex-[1_0_0] flex-col gap-[12px] items-start min-w-px overflow-clip pt-[24px] relative" data-name="Step 01">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#605d5d] text-[20px] whitespace-nowrap">01</p>
      <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#f2f0ef] text-[22px] whitespace-nowrap">Download</p>
      <p className="[word-break:break-word] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] min-w-full relative shrink-0 text-[#9a9695] text-[16px] w-[min-content]">One file for your system, or pip install. Nothing else to install.</p>
      <Fragment />
    </div>
  );
}

function Authorized() {
  return (
    <div className="content-stretch flex gap-[10px] items-center overflow-clip relative shrink-0" data-name="Authorized">
      <div className="bg-[#22d3a6] relative shrink-0 size-[16px]" data-name="Rectangle" />
      <p className="[word-break:break-word] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#9a9695] text-[13px] whitespace-nowrap">I am authorized to scan this target</p>
    </div>
  );
}

function Fragment1() {
  return (
    <div className="bg-[#151414] border border-[#2a2828] border-solid content-stretch flex flex-col gap-[8px] items-start overflow-clip p-[14px] relative shrink-0 w-full" data-name="Fragment">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#f2f0ef] text-[13px] whitespace-nowrap">{`https://staging.example.com`}</p>
      <Authorized />
    </div>
  );
}

function Step1() {
  return (
    <div className="border-[#2a2828] border-solid border-t content-stretch flex flex-[1_0_0] flex-col gap-[12px] items-start min-w-px overflow-clip pt-[24px] relative" data-name="Step 02">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#605d5d] text-[20px] whitespace-nowrap">02</p>
      <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#f2f0ef] text-[22px] whitespace-nowrap">Point it at your site</p>
      <p className="[word-break:break-word] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] min-w-full relative shrink-0 text-[#9a9695] text-[16px] w-[min-content]">{`Paste a URL you're allowed to test and confirm you're authorized.`}</p>
      <Fragment1 />
    </div>
  );
}

function ReflectedXssInQParameter() {
  return (
    <div className="content-stretch flex gap-[10px] items-center overflow-clip relative shrink-0" data-name="Reflected XSS in ?q parameter">
      <SeverityPill className="relative rounded-[2px] shrink-0" />
      <p className="[word-break:break-word] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#f2f0ef] text-[13px] whitespace-nowrap">Reflected XSS in ?q parameter</p>
    </div>
  );
}

function CookieWithoutSecureFlag() {
  return (
    <div className="content-stretch flex gap-[10px] items-center overflow-clip relative shrink-0" data-name="Cookie without Secure flag">
      <SeverityPill className="relative rounded-[2px] shrink-0" severity="medium" />
      <p className="[word-break:break-word] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#f2f0ef] text-[13px] whitespace-nowrap">Cookie without Secure flag</p>
    </div>
  );
}

function MissingXContentTypeOptions() {
  return (
    <div className="content-stretch flex gap-[10px] items-center overflow-clip relative shrink-0" data-name="Missing X-Content-Type-Options">
      <SeverityPill className="relative rounded-[2px] shrink-0" severity="low" />
      <p className="[word-break:break-word] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#f2f0ef] text-[13px] whitespace-nowrap">Missing X-Content-Type-Options</p>
    </div>
  );
}

function Fragment2() {
  return (
    <div className="bg-[#151414] border border-[#2a2828] border-solid content-stretch flex flex-col gap-[8px] items-start overflow-clip p-[14px] relative shrink-0 w-full" data-name="Fragment">
      <ReflectedXssInQParameter />
      <CookieWithoutSecureFlag />
      <MissingXContentTypeOptions />
    </div>
  );
}

function Step2() {
  return (
    <div className="border-[#2a2828] border-solid border-t content-stretch flex flex-[1_0_0] flex-col gap-[12px] items-start min-w-px overflow-clip pt-[24px] relative" data-name="Step 03">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#605d5d] text-[20px] whitespace-nowrap">03</p>
      <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#f2f0ef] text-[22px] whitespace-nowrap">Read the report</p>
      <p className="[word-break:break-word] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] min-w-full relative shrink-0 text-[#9a9695] text-[16px] w-[min-content]">Every finding explained: what it is, how to check it, how to fix it.</p>
      <Fragment2 />
    </div>
  );
}

function Steps() {
  return (
    <div className="content-stretch flex gap-[48px] items-start overflow-clip pt-[48px] relative shrink-0 w-full" data-name="Steps">
      <Step />
      <Step1 />
      <Step2 />
    </div>
  );
}

function HowItWorks() {
  return (
    <div className="content-stretch flex flex-col gap-[16px] items-start overflow-clip pt-[128px] px-[120px] relative shrink-0 w-full" data-name="How it works">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] tracking-[1.68px] whitespace-nowrap">HOW IT WORKS</p>
      <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[60px] relative shrink-0 text-[#f2f0ef] text-[56px] tracking-[-1.68px] whitespace-nowrap">Three steps. No account. No cloud.</p>
      <Steps />
    </div>
  );
}

function Gap() {
  return <div className="h-[40px] relative shrink-0 w-[10px]" data-name="gap" />;
}

function Links1() {
  return (
    <div className="[word-break:break-word] content-stretch flex font-['Space_Grotesk:Medium',sans-serif] font-medium gap-[28px] items-start leading-[normal] overflow-clip pt-[24px] relative shrink-0 text-[#f2f0ef] text-[16px] whitespace-nowrap" data-name="Links">
      <p className="relative shrink-0">Download sample Markdown →</p>
      <p className="relative shrink-0">Download sample JSON →</p>
    </div>
  );
}

function SampleReport() {
  return (
    <div className="content-stretch flex flex-col gap-[16px] items-center overflow-clip pt-[128px] px-[120px] relative shrink-0 w-full" data-name="Sample report">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] tracking-[1.68px] whitespace-nowrap">SAMPLE REPORT</p>
      <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[60px] relative shrink-0 text-[#f2f0ef] text-[56px] tracking-[-1.68px] whitespace-nowrap">This is exactly what you get.</p>
      <p className="[word-break:break-word] font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#9a9695] text-[18px] whitespace-nowrap">A real scan of our demo target. Click any finding.</p>
      <Gap />
      <Report className="bg-[#151414] h-[760px] relative shrink-0 w-full" />
      <Links1 />
    </div>
  );
}

function Description() {
  return (
    <div className="content-stretch flex flex-[1_0_0] flex-col font-normal gap-[6px] items-start min-w-px overflow-clip relative" data-name="Description">
      <p className="font-['Space_Grotesk:Regular',sans-serif] min-w-full relative shrink-0 text-[#9a9695] text-[17px] w-[min-content]">{`Finds places where your site echoes input back as code a visitor's browser would run.`}</p>
      <p className="font-['JetBrains_Mono:Regular',sans-serif] relative shrink-0 text-[#605d5d] text-[12px] whitespace-nowrap">reflected · stored · DOM</p>
    </div>
  );
}

function Xss() {
  return (
    <div className="border-[#2a2828] border-b border-solid border-t content-stretch flex gap-[24px] items-start overflow-clip px-[8px] py-[28px] relative shrink-0 w-full" data-name="XSS">
      <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold relative shrink-0 text-[#f2f0ef] text-[26px] w-[360px]">XSS</p>
      <Description />
    </div>
  );
}

function Description1() {
  return (
    <div className="content-stretch flex flex-[1_0_0] flex-col font-normal gap-[6px] items-start min-w-px overflow-clip relative" data-name="Description">
      <p className="font-['Space_Grotesk:Regular',sans-serif] min-w-full relative shrink-0 text-[#9a9695] text-[17px] w-[min-content]">Checks the protective headers your server should send with every page.</p>
      <p className="font-['JetBrains_Mono:Regular',sans-serif] relative shrink-0 text-[#605d5d] text-[12px] whitespace-nowrap">CSP · HSTS · X-Frame-Options</p>
    </div>
  );
}

function SecurityHeaders() {
  return (
    <div className="border-[#2a2828] border-b border-solid content-stretch flex gap-[24px] items-start overflow-clip px-[8px] py-[28px] relative shrink-0 w-full" data-name="Security headers">
      <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold relative shrink-0 text-[#f2f0ef] text-[26px] w-[360px]">Security headers</p>
      <Description1 />
    </div>
  );
}

function Description2() {
  return (
    <div className="content-stretch flex flex-[1_0_0] flex-col font-normal gap-[6px] items-start min-w-px overflow-clip relative" data-name="Description">
      <p className="font-['Space_Grotesk:Regular',sans-serif] min-w-full relative shrink-0 text-[#9a9695] text-[17px] w-[min-content]">Checks your HTTPS setup for old protocols and expiring certificates.</p>
      <p className="font-['JetBrains_Mono:Regular',sans-serif] relative shrink-0 text-[#605d5d] text-[12px] whitespace-nowrap">TLS 1.0 · ciphers · expiry</p>
    </div>
  );
}

function TlsCertificates() {
  return (
    <div className="border-[#2a2828] border-b border-solid content-stretch flex gap-[24px] items-start overflow-clip px-[8px] py-[28px] relative shrink-0 w-full" data-name="TLS / certificates">
      <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold relative shrink-0 text-[#f2f0ef] text-[26px] w-[360px]">TLS / certificates</p>
      <Description2 />
    </div>
  );
}

function Description3() {
  return (
    <div className="content-stretch flex flex-[1_0_0] flex-col font-normal gap-[6px] items-start min-w-px overflow-clip relative" data-name="Description">
      <p className="font-['Space_Grotesk:Regular',sans-serif] min-w-full relative shrink-0 text-[#9a9695] text-[17px] w-[min-content]">Finds inputs that can reach your database and change its queries.</p>
      <p className="font-['JetBrains_Mono:Regular',sans-serif] relative shrink-0 text-[#605d5d] text-[12px] whitespace-nowrap">error-based · blind</p>
    </div>
  );
}

function SqlInjection() {
  return (
    <div className="border-[#2a2828] border-b border-solid content-stretch flex gap-[24px] items-start overflow-clip px-[8px] py-[28px] relative shrink-0 w-full" data-name="SQL injection">
      <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold relative shrink-0 text-[#f2f0ef] text-[26px] w-[360px]">SQL injection</p>
      <Description3 />
    </div>
  );
}

function Description4() {
  return (
    <div className="content-stretch flex flex-[1_0_0] flex-col font-normal gap-[6px] items-start min-w-px overflow-clip relative" data-name="Description">
      <p className="font-['Space_Grotesk:Regular',sans-serif] min-w-full relative shrink-0 text-[#9a9695] text-[17px] w-[min-content]">Checks forms for anti-forgery tokens and cookies for safe flags.</p>
      <p className="font-['JetBrains_Mono:Regular',sans-serif] relative shrink-0 text-[#605d5d] text-[12px] whitespace-nowrap">tokens · SameSite · Secure</p>
    </div>
  );
}

function CsrfCookies() {
  return (
    <div className="border-[#2a2828] border-b border-solid content-stretch flex gap-[24px] items-start overflow-clip px-[8px] py-[28px] relative shrink-0 w-full" data-name="CSRF & cookies">
      <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold relative shrink-0 text-[#f2f0ef] text-[26px] w-[360px]">{`CSRF & cookies`}</p>
      <Description4 />
    </div>
  );
}

function CheckList() {
  return (
    <div className="content-stretch flex flex-col items-start leading-[normal] overflow-clip pt-[40px] relative shrink-0 w-full" data-name="Check list">
      <Xss />
      <SecurityHeaders />
      <TlsCertificates />
      <SqlInjection />
      <CsrfCookies />
    </div>
  );
}

function WhatItChecks() {
  return (
    <div className="[word-break:break-word] content-stretch flex flex-col gap-[16px] items-start overflow-clip pt-[128px] px-[120px] relative shrink-0 w-full" data-name="What it checks">
      <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] tracking-[1.68px] whitespace-nowrap">WHAT IT CHECKS</p>
      <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[60px] relative shrink-0 text-[#f2f0ef] text-[56px] tracking-[-1.68px] whitespace-nowrap">Five checks. Every finding explained.</p>
      <CheckList />
    </div>
  );
}

function LocalFirst() {
  return (
    <div className="content-stretch flex flex-[1_0_0] flex-col gap-[8px] items-start min-w-px overflow-clip relative" data-name="LOCAL-FIRST">
      <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium relative shrink-0 text-[#9a9695] text-[11px] whitespace-nowrap">LOCAL-FIRST</p>
      <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold relative shrink-0 text-[#f2f0ef] text-[20px] whitespace-nowrap">Runs on localhost.</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal min-w-full relative shrink-0 text-[#9a9695] text-[16px] w-[min-content]">No telemetry, no account, works offline.</p>
    </div>
  );
}

function OpenSource() {
  return (
    <div className="content-stretch flex flex-[1_0_0] flex-col gap-[8px] items-start min-w-px overflow-clip relative" data-name="OPEN-SOURCE">
      <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium relative shrink-0 text-[#9a9695] text-[11px] whitespace-nowrap">OPEN-SOURCE</p>
      <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold relative shrink-0 text-[#f2f0ef] text-[20px] whitespace-nowrap">Every check is on GitHub.</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal min-w-full relative shrink-0 text-[#9a9695] text-[16px] w-[min-content]">Read it, run it, audit it.</p>
    </div>
  );
}

function Row() {
  return (
    <div className="content-stretch flex gap-[80px] items-start overflow-clip relative shrink-0 w-full" data-name="Row">
      <LocalFirst />
      <OpenSource />
    </div>
  );
}

function SelfTested() {
  return (
    <div className="content-stretch flex flex-[1_0_0] flex-col gap-[8px] items-start min-w-px overflow-clip relative" data-name="SELF-TESTED">
      <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium relative shrink-0 text-[#9a9695] text-[11px] whitespace-nowrap">SELF-TESTED</p>
      <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold relative shrink-0 text-[#f2f0ef] text-[20px] whitespace-nowrap">We scan WebScanX with WebScanX.</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal min-w-full relative shrink-0 text-[#9a9695] text-[16px] w-[min-content]">Every release is scanned before we publish it.</p>
    </div>
  );
}

function AuthorizationGated() {
  return (
    <div className="content-stretch flex flex-[1_0_0] flex-col gap-[8px] items-start min-w-px overflow-clip relative" data-name="AUTHORIZATION-GATED">
      <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium relative shrink-0 text-[#9a9695] text-[11px] whitespace-nowrap">AUTHORIZATION-GATED</p>
      <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold relative shrink-0 text-[#f2f0ef] text-[20px] whitespace-nowrap">{`It won't start until you confirm.`}</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal min-w-full relative shrink-0 text-[#9a9695] text-[16px] w-[min-content]">{`You tick "I am authorized" before any scan can start.`}</p>
    </div>
  );
}

function Row1() {
  return (
    <div className="content-stretch flex gap-[80px] items-start overflow-clip relative shrink-0 w-full" data-name="Row">
      <SelfTested />
      <AuthorizationGated />
    </div>
  );
}

function Grid() {
  return (
    <div className="content-stretch flex flex-col gap-[56px] items-start leading-[normal] overflow-clip pt-[56px] relative shrink-0 w-full" data-name="Grid">
      <Row />
      <Row1 />
    </div>
  );
}

function WhyTrustIt() {
  return (
    <div className="[word-break:break-word] content-stretch flex flex-col gap-[16px] items-center overflow-clip pt-[128px] px-[230px] relative shrink-0 w-full" data-name="Why trust it">
      <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] tracking-[1.68px] whitespace-nowrap">WHY TRUST IT</p>
      <p className="font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[60px] relative shrink-0 text-[#f2f0ef] text-[56px] tracking-[-1.68px] whitespace-nowrap">{`Built so you don't have to trust us.`}</p>
      <Grid />
    </div>
  );
}

function Gap1() {
  return <div className="h-[40px] relative shrink-0 w-[10px]" data-name="gap" />;
}

function Checksum() {
  return (
    <div className="border-[#2a2828] border-solid border-t content-stretch flex items-start overflow-clip pt-[14px] relative shrink-0 w-full" data-name="Checksum">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#605d5d] text-[11px] whitespace-nowrap">SHA-256 8f4b2a67…e109</p>
    </div>
  );
}

function Windows() {
  return (
    <div className="border-[#2a2828] border-r border-solid content-stretch flex flex-[1_0_0] flex-col gap-[8px] items-start min-w-px overflow-clip px-[28px] py-[32px] relative" data-name="Windows">
      <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#f2f0ef] text-[28px] whitespace-nowrap">Windows</p>
      <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] whitespace-nowrap">.exe · 24 MB · Windows 10/11</p>
      <Button className="bg-[#22d3a6] h-[36px] relative shrink-0" label="Download .exe" />
      <Checksum />
    </div>
  );
}

function Checksum1() {
  return (
    <div className="border-[#2a2828] border-solid border-t content-stretch flex items-start overflow-clip pt-[14px] relative shrink-0 w-full" data-name="Checksum">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#605d5d] text-[11px] whitespace-nowrap">SHA-256 3c7a188f…fa82</p>
    </div>
  );
}

function MacOs() {
  return (
    <div className="border-[#2a2828] border-r border-solid content-stretch flex flex-[1_0_0] flex-col gap-[8px] items-start min-w-px overflow-clip px-[28px] py-[32px] relative" data-name="macOS">
      <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#f2f0ef] text-[28px] whitespace-nowrap">macOS</p>
      <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] whitespace-nowrap">.dmg · 28 MB · Apple Silicon + Intel</p>
      <Button className="bg-[#22d3a6] h-[36px] relative shrink-0" label="Download .dmg" />
      <Checksum1 />
    </div>
  );
}

function Checksum2() {
  return (
    <div className="border-[#2a2828] border-solid border-t content-stretch flex items-start overflow-clip pt-[14px] relative shrink-0 w-full" data-name="Checksum">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#605d5d] text-[11px] whitespace-nowrap">SHA-256 d5a26ba6…77b1</p>
    </div>
  );
}

function Linux() {
  return (
    <div className="border-0 border-[#2a2828] border-solid content-stretch flex flex-[1_0_0] flex-col gap-[8px] items-start min-w-px overflow-clip px-[28px] py-[32px] relative" data-name="Linux">
      <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[normal] relative shrink-0 text-[#f2f0ef] text-[28px] whitespace-nowrap">Linux</p>
      <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] whitespace-nowrap">.AppImage · 22 MB · x86_64</p>
      <Button className="bg-[#22d3a6] h-[36px] relative shrink-0" label="Download .AppImage" />
      <Checksum2 />
    </div>
  );
}

function Platforms() {
  return (
    <div className="border-[#2a2828] border-b border-solid border-t content-stretch flex items-start overflow-clip relative shrink-0 w-full" data-name="Platforms">
      <Windows />
      <MacOs />
      <Linux />
    </div>
  );
}

function Gap2() {
  return <div className="h-[24px] relative shrink-0 w-[10px]" data-name="gap" />;
}

function Pip() {
  return (
    <div className="bg-[#151414] border border-[#2a2828] border-solid content-stretch flex items-start overflow-clip px-[16px] py-[10px] relative shrink-0" data-name="pip">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#f2f0ef] text-[14px] whitespace-nowrap">pip install webscanx</p>
    </div>
  );
}

function SmallLinks() {
  return (
    <div className="[word-break:break-word] content-stretch flex font-['Space_Grotesk:Regular',sans-serif] font-normal gap-[28px] items-start leading-[normal] overflow-clip relative shrink-0 text-[#9a9695] text-[14px] whitespace-nowrap" data-name="Small links">
      <p className="relative shrink-0">Release notes</p>
      <p className="relative shrink-0">Verify signature</p>
      <p className="relative shrink-0">System requirements</p>
    </div>
  );
}

function Download() {
  return (
    <div className="content-stretch flex flex-col gap-[16px] items-center overflow-clip pt-[128px] px-[120px] relative shrink-0 w-full" data-name="Download">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Medium',sans-serif] font-medium leading-[normal] relative shrink-0 text-[#9a9695] text-[12px] tracking-[1.68px] whitespace-nowrap">DOWNLOAD</p>
      <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[60px] relative shrink-0 text-[#f2f0ef] text-[56px] tracking-[-1.68px] whitespace-nowrap">Download WebScanX v1.0</p>
      <Gap1 />
      <Platforms />
      <Gap2 />
      <Pip />
      <SmallLinks />
    </div>
  );
}

function Question() {
  return (
    <div className="[word-break:break-word] content-stretch flex font-normal items-start justify-between leading-[normal] overflow-clip relative shrink-0 text-[20px] w-full whitespace-nowrap" data-name="Question">
      <p className="font-['Space_Grotesk:Regular',sans-serif] relative shrink-0 text-[#f2f0ef]">Does anything get uploaded?</p>
      <p className="font-['JetBrains_Mono:Regular',sans-serif] relative shrink-0 text-[#9a9695]">+</p>
    </div>
  );
}

function DoesAnythingGetUploaded() {
  return (
    <div className="border-[#2a2828] border-b border-solid content-stretch flex flex-col items-start overflow-clip py-[24px] relative shrink-0 w-full" data-name="Does anything get uploaded?">
      <Question />
    </div>
  );
}

function Question1() {
  return (
    <div className="[word-break:break-word] content-stretch flex font-normal items-start justify-between leading-[normal] overflow-clip relative shrink-0 text-[20px] w-full whitespace-nowrap" data-name="Question">
      <p className="font-['Space_Grotesk:Regular',sans-serif] relative shrink-0 text-[#f2f0ef]">Is it legal to scan a website?</p>
      <p className="font-['JetBrains_Mono:Regular',sans-serif] relative shrink-0 text-[#9a9695]">+</p>
    </div>
  );
}

function IsItLegalToScanAWebsite() {
  return (
    <div className="border-[#2a2828] border-b border-solid content-stretch flex flex-col items-start overflow-clip py-[24px] relative shrink-0 w-full" data-name="Is it legal to scan a website?">
      <Question1 />
    </div>
  );
}

function Question2() {
  return (
    <div className="content-stretch flex items-start justify-between overflow-clip relative shrink-0 text-[20px] w-full whitespace-nowrap" data-name="Question">
      <p className="font-['Space_Grotesk:Regular',sans-serif] relative shrink-0 text-[#f2f0ef]">Does it fix vulnerabilities?</p>
      <p className="font-['JetBrains_Mono:Regular',sans-serif] relative shrink-0 text-[#9a9695]">−</p>
    </div>
  );
}

function DoesItFixVulnerabilities() {
  return (
    <div className="[word-break:break-word] border-[#2a2828] border-b border-solid content-stretch flex flex-col font-normal gap-[12px] items-start leading-[normal] overflow-clip py-[24px] relative shrink-0 w-full" data-name="Does it fix vulnerabilities?">
      <Question2 />
      <p className="font-['Space_Grotesk:Regular',sans-serif] relative shrink-0 text-[#9a9695] text-[16px] w-full">No. v1 finds and explains each issue and shows you how to fix it yourself. It never changes your site.</p>
    </div>
  );
}

function Question3() {
  return (
    <div className="[word-break:break-word] content-stretch flex font-normal items-start justify-between leading-[normal] overflow-clip relative shrink-0 text-[20px] w-full whitespace-nowrap" data-name="Question">
      <p className="font-['Space_Grotesk:Regular',sans-serif] relative shrink-0 text-[#f2f0ef]">What does it need to run?</p>
      <p className="font-['JetBrains_Mono:Regular',sans-serif] relative shrink-0 text-[#9a9695]">+</p>
    </div>
  );
}

function WhatDoesItNeedToRun() {
  return (
    <div className="border-[#2a2828] border-b border-solid content-stretch flex flex-col items-start overflow-clip py-[24px] relative shrink-0 w-full" data-name="What does it need to run?">
      <Question3 />
    </div>
  );
}

function Question4() {
  return (
    <div className="[word-break:break-word] content-stretch flex font-normal items-start justify-between leading-[normal] overflow-clip relative shrink-0 text-[20px] w-full whitespace-nowrap" data-name="Question">
      <p className="font-['Space_Grotesk:Regular',sans-serif] relative shrink-0 text-[#f2f0ef]">Is it free?</p>
      <p className="font-['JetBrains_Mono:Regular',sans-serif] relative shrink-0 text-[#9a9695]">+</p>
    </div>
  );
}

function IsItFree() {
  return (
    <div className="border-[#2a2828] border-b border-solid content-stretch flex flex-col items-start overflow-clip py-[24px] relative shrink-0 w-full" data-name="Is it free?">
      <Question4 />
    </div>
  );
}

function Accordion() {
  return (
    <div className="border-[#2a2828] border-solid border-t content-stretch flex flex-col items-start overflow-clip relative shrink-0 w-full" data-name="Accordion">
      <DoesAnythingGetUploaded />
      <IsItLegalToScanAWebsite />
      <DoesItFixVulnerabilities />
      <WhatDoesItNeedToRun />
      <IsItFree />
    </div>
  );
}

function Faq() {
  return (
    <div className="content-stretch flex flex-col gap-[48px] items-start overflow-clip px-[120px] py-[128px] relative shrink-0 w-full" data-name="FAQ">
      <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[60px] relative shrink-0 text-[#f2f0ef] text-[56px] tracking-[-1.68px] whitespace-nowrap">Questions</p>
      <Accordion />
    </div>
  );
}

function Brand() {
  return (
    <div className="content-stretch flex flex-[1_0_0] flex-col gap-[10px] items-start min-w-px overflow-clip relative" data-name="Brand">
      <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium relative shrink-0 text-[#f2f0ef] text-[17px]">WebScanX</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal relative shrink-0 text-[#9a9695] text-[14px]">Local web vulnerability scanner.</p>
    </div>
  );
}

function Product() {
  return (
    <div className="content-stretch flex flex-col gap-[8px] items-start overflow-clip relative shrink-0 w-[220px]" data-name="PRODUCT">
      <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium relative shrink-0 text-[#605d5d] text-[11px]">PRODUCT</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal relative shrink-0 text-[#9a9695] text-[14px]">Download</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal relative shrink-0 text-[#9a9695] text-[14px]">Docs</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal relative shrink-0 text-[#9a9695] text-[14px]">Sample report</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal relative shrink-0 text-[#9a9695] text-[14px]">Dashboard demo</p>
    </div>
  );
}

function Project() {
  return (
    <div className="content-stretch flex flex-col gap-[8px] items-start overflow-clip relative shrink-0 w-[220px]" data-name="PROJECT">
      <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium relative shrink-0 text-[#605d5d] text-[11px]">PROJECT</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal relative shrink-0 text-[#9a9695] text-[14px]">GitHub</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal relative shrink-0 text-[#9a9695] text-[14px]">Security policy</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal relative shrink-0 text-[#9a9695] text-[14px]">License</p>
    </div>
  );
}

function Legal() {
  return (
    <div className="content-stretch flex flex-col gap-[8px] items-start overflow-clip relative shrink-0 w-[220px]" data-name="LEGAL">
      <p className="font-['JetBrains_Mono:Medium',sans-serif] font-medium relative shrink-0 text-[#605d5d] text-[11px]">LEGAL</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal relative shrink-0 text-[#9a9695] text-[14px]">Responsible use</p>
      <p className="font-['Space_Grotesk:Regular',sans-serif] font-normal relative shrink-0 text-[#9a9695] text-[14px]">Privacy</p>
    </div>
  );
}

function Columns() {
  return (
    <div className="[word-break:break-word] content-stretch flex gap-[32px] items-start leading-[normal] overflow-clip relative shrink-0 w-full whitespace-nowrap" data-name="Columns">
      <Brand />
      <Product />
      <Project />
      <Legal />
    </div>
  );
}

function Bottom() {
  return (
    <div className="border-[#2a2828] border-solid border-t content-stretch flex items-start overflow-clip pt-[20px] relative shrink-0 w-full" data-name="Bottom">
      <p className="[word-break:break-word] font-['JetBrains_Mono:Regular',sans-serif] font-normal leading-[normal] relative shrink-0 text-[#605d5d] text-[12px] whitespace-nowrap">© 2026 WebScanX · Runs locally.</p>
    </div>
  );
}

function Footer() {
  return (
    <div className="border-[#2a2828] border-solid border-t content-stretch flex flex-col gap-[48px] items-start overflow-clip pt-[64px] px-[120px] relative shrink-0 w-full" data-name="Footer">
      <Columns />
      <Bottom />
      <p className="[word-break:break-word] font-['Space_Grotesk:Bold',sans-serif] font-bold leading-[0.8] relative shrink-0 text-[#151414] text-[240px] text-center tracking-[-12px] w-full">WEBSCANX</p>
    </div>
  );
}

export default function ShopLanding() {
  return (
    <div className="bg-[#0d0c0c] content-stretch flex flex-col items-start relative size-full" data-name="Shop — Landing (1440)">
      <Nav />
      <Hero />
      <Statement />
      <HowItWorks />
      <SampleReport />
      <WhatItChecks />
      <WhyTrustIt />
      <Download />
      <Faq />
      <Footer />
    </div>
  );
}