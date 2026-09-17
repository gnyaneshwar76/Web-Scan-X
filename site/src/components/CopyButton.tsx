import { useState } from "react";

type Props = {
  text: string;
  className?: string;
};

export default function CopyButton({ text, className = "" }: Props) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <button
      onClick={copy}
      title="Copy to clipboard"
      className={`text-muted-text hover:text-primary-text transition-colors ${className}`}
    >
      {copied ? (
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <path d="M2.5 7L5.5 10L11.5 4" stroke="#22d3a6" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      ) : (
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <rect x="4.5" y="1.5" width="8" height="9" rx="0" stroke="currentColor" strokeWidth="1.2" />
          <rect x="1.5" y="3.5" width="8" height="9" rx="0" stroke="currentColor" strokeWidth="1.2" fill="#0d0c0c" />
        </svg>
      )}
    </button>
  );
}
