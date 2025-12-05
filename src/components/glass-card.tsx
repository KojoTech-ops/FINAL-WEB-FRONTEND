import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface GlassCardProps {
  children: React.ReactNode;
  className?: string;
  glowColor?: "cyan" | "magenta" | "gold" | "none";
}

export function GlassCard({ children, className, glowColor = "cyan" }: GlassCardProps) {
  const glowClasses = {
    cyan: "shadow-[0_0_20px_rgba(0,240,255,0.15)] border-primary/20",
    magenta: "shadow-[0_0_20px_rgba(255,0,255,0.15)] border-neon-magenta/20",
    gold: "shadow-[0_0_20px_rgba(255,215,0,0.15)] border-gold/20",
    none: "",
  };

  return (
    <Card
      className={cn(
        "backdrop-blur-xl bg-card/40 border hover-elevate transition-all duration-300 overflow-hidden",
        glowClasses[glowColor],
        className
      )}
    >
      {children}
    </Card>
  );
}
