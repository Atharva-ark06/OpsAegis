import { useEffect, useState } from "react";
import { Plus } from "lucide-react";

export interface PrismFluxLoaderProps {
  size?: number;
  speed?: number;
  textSize?: number;
}

const STATUSES = ["Fetching", "Fixing", "Updating", "Placing", "Syncing", "Processing"];
const FACE_TRANSFORMS = [
  (half: number) => `rotateY(0deg) translateZ(${half}px)`,
  (half: number) => `rotateY(180deg) translateZ(${half}px)`,
  (half: number) => `rotateY(90deg) translateZ(${half}px)`,
  (half: number) => `rotateY(-90deg) translateZ(${half}px)`,
  (half: number) => `rotateX(90deg) translateZ(${half}px)`,
  (half: number) => `rotateX(-90deg) translateZ(${half}px)`,
];

export function PrismFluxLoader({ size = 64, speed = 5, textSize = 28 }: PrismFluxLoaderProps) {
  const [rotation, setRotation] = useState(0);
  const [statusIndex, setStatusIndex] = useState(0);
  const half = size / 2;

  useEffect(() => {
    const frame = window.setInterval(() => setRotation((current) => current + 0.02 * speed), 16);
    return () => window.clearInterval(frame);
  }, [speed]);

  useEffect(() => {
    const statusTimer = window.setInterval(() => setStatusIndex((current) => (current + 1) % STATUSES.length), 600);
    return () => window.clearInterval(statusTimer);
  }, []);

  return (
    <main className="prism-flux-screen" role="status" aria-live="polite" aria-label="Preparing your OpsAegis workspace">
      <div className="prism-flux-content">
        <div className="prism-flux-perspective">
          <div className="prism-flux-cube" style={{ width: size, height: size, transform: `rotateY(${rotation * 30}deg) rotateX(${rotation * 30}deg)` }}>
            {FACE_TRANSFORMS.map((transform, index) => (
              <div className="prism-flux-face" key={index} style={{ width: size, height: size, transform: transform(half) }} aria-hidden="true">
                <Plus size={textSize} strokeWidth={2.2} />
              </div>
            ))}
          </div>
        </div>
        <p className="prism-flux-status">{STATUSES[statusIndex]}...</p>
        <span className="sr-only">Signing you in and preparing the security operations dashboard.</span>
      </div>
    </main>
  );
}

export default PrismFluxLoader;
