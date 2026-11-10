import type { ButtonHTMLAttributes, ReactNode } from "react";
import "./theme-toggle.css";

export type ThemeMode = "light" | "dark";

export interface ThemeToggleProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "onChange"> {
  mode: ThemeMode;
  onModeChange: (mode: ThemeMode, trigger: HTMLButtonElement) => void;
  showLabel?: boolean;
  label?: ReactNode;
  /** Keep the icon-only 44px target on narrow screens. */
  responsive?: boolean;
}

/** Controlled theme switch. The app owns persistence and the page theme. */
export function ThemeToggle({
  mode,
  onModeChange,
  showLabel = true,
  label,
  responsive = false,
  className = "",
  onClick,
  ...props
}: ThemeToggleProps) {
  const dark = mode === "dark";
  const nextMode: ThemeMode = dark ? "light" : "dark";

  return (
    <button
      {...props}
      type="button"
      role="switch"
      aria-checked={dark}
      aria-label="Dark appearance"
      title={`Switch to ${nextMode} theme`}
      data-responsive={responsive ? "true" : "false"}
      className={`aegis-theme-toggle ${className}`.trim()}
      onClick={(event) => {
        onClick?.(event);
        if (!event.defaultPrevented) onModeChange(nextMode, event.currentTarget);
      }}
    >
      <svg
        className="aegis-theme-toggle-icon"
        viewBox="0 0 24 24"
        width="22"
        height="22"
        fill="none"
        aria-hidden="true"
        focusable="false"
      >
        <g className={`aegis-theme-rays ${dark ? "is-hidden" : ""}`}>
          {Array.from({ length: 8 }, (_, index) => (
            <path
              key={index}
              d="M12 1.5V3"
              transform={`rotate(${index * 45} 12 12)`}
              stroke="currentColor"
              strokeWidth="1.6"
              strokeLinecap="round"
            />
          ))}
        </g>
        <path
          className={`aegis-theme-sun ${dark ? "is-hidden" : ""}`}
          d="M12 5C15.866 5 19 8.134 19 12C19 15.866 15.866 19 12 19C8.134 19 5 15.866 5 12C5 8.134 8.134 5 12 5Z"
          fill="currentColor"
        />
        <path
          className={`aegis-theme-moon ${dark ? "is-visible" : ""}`}
          d="M18.9 15.2C17.2 19.3 12.9 21.2 8.8 19.4C4.7 17.6 2.7 13 4.4 8.8C5.4 6.2 7.7 4.3 10.4 3.8C8.1 10.4 12.3 16.8 18.9 15.2Z"
          fill="currentColor"
        />
      </svg>
      {showLabel && (
        <span className="aegis-theme-toggle-label">
          {label ?? (dark ? "Dark" : "Light")}
        </span>
      )}
    </button>
  );
}

export default ThemeToggle;
