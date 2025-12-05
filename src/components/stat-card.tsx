import { GlassCard } from "./glass-card";
import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  change?: string;
  trend?: "up" | "down" | "neutral";
  glowColor?: "cyan" | "magenta" | "gold" | "none";
  className?: string;
}

export function StatCard({ title, value, icon: Icon, change, trend, glowColor = "cyan", className }: StatCardProps) {
  const trendColors = {
    up: "text-neon-green",
    down: "text-destructive",
    neutral: "text-muted-foreground",
  };

  return (
    <GlassCard glowColor={glowColor} className={cn("p-6 overflow-hidden", className)}>
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-2 flex-1 min-w-0">
          <p className="text-sm text-muted-foreground font-medium truncate" data-testid={`stat-title-${title.toLowerCase().replace(/\s/g, '-')}`}>{title}</p>
          <p className="text-2xl sm:text-3xl font-bold truncate" data-testid={`stat-value-${title.toLowerCase().replace(/\s/g, '-')}`}>{value}</p>
          {change && trend && (
            <p className={cn("text-sm font-medium truncate", trendColors[trend])} data-testid={`stat-change-${title.toLowerCase().replace(/\s/g, '-')}`}>
              {change}
            </p>
          )}
        </div>
        <div className="p-3 rounded-lg bg-primary/10 flex-shrink-0">
          <Icon className="w-6 h-6 text-primary" />
        </div>
      </div>
    </GlassCard>
  );
}
