import { liquidMetalFragmentShader, ShaderMount } from "@paper-design/shaders";
import { Sparkles } from "lucide-react";
import type React from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import "./liquid-metal-button.css";

interface LiquidMetalButtonProps {
  label?: string;
  onClick?: () => void;
  viewMode?: "text" | "icon";
}

interface ShaderMountHandle {
  destroy?: () => void;
  setSpeed?: (speed: number) => void;
}

interface Ripple {
  x: number;
  y: number;
  id: number;
}

export function LiquidMetalButton({
  label = "Get Started",
  onClick,
  viewMode = "text",
}: LiquidMetalButtonProps) {
  const [isHovered, setIsHovered] = useState(false);
  const [isPressed, setIsPressed] = useState(false);
  const [ripples, setRipples] = useState<Ripple[]>([]);
  const shaderRef = useRef<HTMLDivElement>(null);
  const shaderMount = useRef<ShaderMountHandle | null>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const rippleId = useRef(0);
  const hoverRef = useRef(false);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  const dimensions = useMemo(() => {
    if (viewMode === "icon") {
      return { width: 46, height: 46, innerWidth: 42, innerHeight: 42 };
    }
    return { width: 142, height: 46, innerWidth: 138, innerHeight: 42 };
  }, [viewMode]);

  useEffect(() => {
    if (!shaderRef.current) return;

    try {
      shaderMount.current = new ShaderMount(
        shaderRef.current,
        liquidMetalFragmentShader,
        {
          u_repetition: 4,
          u_softness: 0.5,
          u_shiftRed: 0.3,
          u_shiftBlue: 0.3,
          u_distortion: 0,
          u_contour: 0,
          u_angle: 45,
          u_scale: 8,
          u_shape: 1,
          u_offsetX: 0.1,
          u_offsetY: -0.1,
        },
        undefined,
        0.6,
      ) as unknown as ShaderMountHandle;
    } catch (error) {
      // Keep the button usable if WebGL is unavailable or shader setup fails.
      console.error("[LiquidMetalButton] Failed to initialize shader:", error);
    }

    return () => {
      timers.current.forEach(clearTimeout);
      timers.current = [];
      shaderMount.current?.destroy?.();
      shaderMount.current = null;
    };
  }, []);

  const handleMouseEnter = () => {
    hoverRef.current = true;
    setIsHovered(true);
    shaderMount.current?.setSpeed?.(1);
  };

  const handleMouseLeave = () => {
    hoverRef.current = false;
    setIsHovered(false);
    setIsPressed(false);
    shaderMount.current?.setSpeed?.(0.6);
  };

  const handleClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    shaderMount.current?.setSpeed?.(2.4);
    const speedTimer = setTimeout(() => {
      shaderMount.current?.setSpeed?.(hoverRef.current ? 1 : 0.6);
    }, 300);
    timers.current.push(speedTimer);

    const rect = buttonRef.current?.getBoundingClientRect();
    if (rect) {
      const ripple = {
        x: event.clientX - rect.left,
        y: event.clientY - rect.top,
        id: rippleId.current++,
      };
      setRipples((previous) => [...previous, ripple]);
      const rippleTimer = setTimeout(() => {
        setRipples((previous) => previous.filter((item) => item.id !== ripple.id));
      }, 600);
      timers.current.push(rippleTimer);
    }

    onClick?.();
  };

  return (
    <div className="liquid-metal-button-wrap">
      <div className="liquid-metal-button-perspective">
        <div
          className="liquid-metal-button-stage"
          style={{ width: dimensions.width, height: dimensions.height }}
        >
          <div
            className="liquid-metal-button-label-layer"
            style={{ width: dimensions.width, height: dimensions.height }}
          >
            {viewMode === "icon" ? (
              <Sparkles className="liquid-metal-button-icon" size={16} aria-hidden="true" />
            ) : (
              <span className="liquid-metal-button-label">{label}</span>
            )}
          </div>

          <div
            className="liquid-metal-button-inner-layer"
            style={{
              width: dimensions.width,
              height: dimensions.height,
              transform: isPressed ? "translateZ(10px) translateY(1px) scale(.98)" : "translateZ(10px)",
            }}
          >
            <div
              className="liquid-metal-button-inner"
              style={{
                width: dimensions.innerWidth,
                height: dimensions.innerHeight,
                boxShadow: isPressed
                  ? "inset 0 2px 4px rgba(0,0,0,.4), inset 0 1px 2px rgba(0,0,0,.3)"
                  : "none",
              }}
            />
          </div>

          <div
            className="liquid-metal-button-shader-layer"
            style={{
              width: dimensions.width,
              height: dimensions.height,
              transform: isPressed ? "translateZ(0) translateY(1px) scale(.98)" : "translateZ(0)",
            }}
          >
            <div
              className={`liquid-metal-button-rim${isHovered ? " is-hovered" : ""}`}
              style={{ width: dimensions.width, height: dimensions.height }}
            >
              <div
                ref={shaderRef}
                className="liquid-metal-button-shader"
                style={{ width: dimensions.width, height: dimensions.height }}
              />
            </div>
          </div>

          <button
            ref={buttonRef}
            type="button"
            className="liquid-metal-button-hit-area"
            style={{ width: dimensions.width, height: dimensions.height }}
            onClick={handleClick}
            onMouseEnter={handleMouseEnter}
            onMouseLeave={handleMouseLeave}
            onMouseDown={() => setIsPressed(true)}
            onMouseUp={() => setIsPressed(false)}
            onBlur={() => setIsPressed(false)}
            aria-label={label}
          >
            {ripples.map((ripple) => (
              <span
                key={ripple.id}
                className="liquid-metal-button-ripple"
                style={{ left: ripple.x, top: ripple.y }}
              />
            ))}
          </button>
        </div>
      </div>
    </div>
  );
}

export default LiquidMetalButton;
