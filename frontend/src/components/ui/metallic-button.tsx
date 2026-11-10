import type { ButtonHTMLAttributes, ReactNode } from "react";
import { Sparkles } from "lucide-react";
import "./metallic-button.css";

export interface MetallicButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children"> {
  label?: string;
  children?: ReactNode;
  viewMode?: "text" | "icon";
}

export function MetallicButton({
  label = "Get Started",
  children,
  viewMode = "text",
  className = "",
  type = "button",
  disabled = false,
  ...buttonProps
}: MetallicButtonProps) {
  const content = children ?? (viewMode === "icon" ? <Sparkles aria-hidden="true" size={16} /> : label);

  return (
    <button
      {...buttonProps}
      type={type}
      disabled={disabled}
      className={`metallic-button ${className}`.trim()}
    >
      <span className="metallic-button-face">
        <span className="metallic-button-content">{content}</span>
      </span>
    </button>
  );
}

export default MetallicButton;
