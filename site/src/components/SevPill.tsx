import { SEV_COLORS, type Severity } from "@/data/findings";

export default function SevPill({ level }: { level: Severity }) {
  const s = SEV_COLORS[level];
  return (
    <span
      className="inline-block mono text-[10px] font-semibold tracking-[0.05em] px-1.5 py-0.5 shrink-0"
      style={{ color: s.text, backgroundColor: s.bg }}
    >
      {level}
    </span>
  );
}
