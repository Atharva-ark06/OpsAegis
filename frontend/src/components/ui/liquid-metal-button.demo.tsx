import { LiquidMetalButton } from "@/components/ui/liquid-metal-button";

export default function LiquidMetalButtonDemo() {
  return (
    <div className="flex flex-col items-center justify-center gap-8 p-8">
      <div className="flex items-center gap-8">
        <LiquidMetalButton label="Get Started" onClick={() => console.info("Get Started clicked")} />
        <LiquidMetalButton label="Open quick actions" viewMode="icon" />
      </div>
    </div>
  );
}
