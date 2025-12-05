import { cn } from "@/lib/utils";

interface GradientTextProps {
  children: React.ReactNode;
  className?: string;
  gradient?: "cyan-magenta" | "gold-cyan" | "magenta-gold";
}

export function GradientText({ children, className, gradient = "cyan-magenta" }: GradientTextProps) {
  const gradients = {
    "cyan-magenta": "bg-gradient-to-r from-neon-cyan to-neon-magenta",
    "gold-cyan": "bg-gradient-to-r from-gold to-neon-cyan",
    "magenta-gold": "bg-gradient-to-r from-neon-magenta to-gold",
  };

  return (
    <span className={cn("bg-clip-text text-transparent", gradients[gradient], className)}>
      {children}
    </span>
  );
}
