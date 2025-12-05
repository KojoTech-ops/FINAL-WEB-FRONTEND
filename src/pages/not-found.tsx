import { AlertCircle } from "lucide-react";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { GlassCard } from "@/components/glass-card";
import { GradientText } from "@/components/gradient-text";

export default function NotFound() {
  return (
    <div className="min-h-[80vh] w-full flex items-center justify-center p-6">
      <GlassCard glowColor="magenta" className="w-full max-w-md p-8 text-center">
        <div className="flex flex-col items-center gap-4">
          <AlertCircle className="h-16 w-16 text-neon-magenta" />
          <h1 className="text-3xl font-bold">
            <GradientText>404</GradientText>
          </h1>
          <p className="text-xl font-semibold text-foreground">Page Not Found</p>
          <p className="text-muted-foreground">
            The page you're looking for doesn't exist or has been moved.
          </p>
          <Link href="/dashboard">
            <Button className="mt-4 bg-gradient-to-r from-neon-cyan to-neon-magenta hover:opacity-90">
              Back to Dashboard
            </Button>
          </Link>
        </div>
      </GlassCard>
    </div>
  );
}
