import { useEffect, useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useQuery } from "@tanstack/react-query";
import { GlassCard } from "@/components/glass-card";
import { StatCard } from "@/components/stat-card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Users, Copy, CheckCircle2, TrendingUp, Gift } from "lucide-react";

export default function Referrals() {
  const { toast } = useToast();
  const { user, isAuthenticated, isLoading } = useAuth();
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      toast({
        title: "Unauthorized",
        description: "You are logged out. Logging in again...",
        variant: "destructive",
      });
      setTimeout(() => {
        window.location.href = "/api/login";
      }, 500);
      return;
    }
  }, [isAuthenticated, isLoading, toast]);

  const { data: referralStats } = useQuery<{
    totalReferrals: number;
    earnedCredits: string;
    conversionRate: string;
  }>({
    queryKey: ["/api/referrals/stats"],
    enabled: isAuthenticated,
  });

  const { data: referralList = [] } = useQuery<Array<{
    id: string;
    referredName: string;
    signupDate: string;
    status: string;
    earnedAmount: string;
  }>>({
    queryKey: ["/api/referrals/list"],
    enabled: isAuthenticated,
  });

  const copyReferralCode = () => {
    if (user?.referralCode) {
      const referralUrl = `${window.location.origin}?ref=${user.referralCode}`;
      navigator.clipboard.writeText(referralUrl);
      setCopied(true);
      toast({
        title: "Copied!",
        description: "Referral link copied to clipboard",
      });
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading referrals...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-7xl mx-auto p-4 sm:p-6 lg:p-8 space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold mb-2">Referral Program</h1>
          <p className="text-muted-foreground">Earn credits by inviting friends</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <StatCard
            title="Total Referrals"
            value={referralStats?.totalReferrals || 0}
            icon={Users}
            glowColor="cyan"
            change="+5 this month"
            trend="up"
          />
          <StatCard
            title="Earned Credits"
            value={`GH₵ ${referralStats?.earnedCredits || "0.00"}`}
            icon={Gift}
            glowColor="gold"
          />
          <StatCard
            title="Conversion Rate"
            value={referralStats?.conversionRate || "0%"}
            icon={TrendingUp}
            glowColor="magenta"
          />
        </div>

        {/* Referral Code */}
        <GlassCard glowColor="gold" className="p-8">
          <div className="text-center max-w-2xl mx-auto space-y-6">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gold/20 mb-4">
              <Gift className="w-8 h-8 text-gold" />
            </div>
            <h2 className="text-2xl font-bold">Your Referral Code</h2>
            <p className="text-muted-foreground">
              Share your unique referral link and earn GH₵5 for each friend who signs up plus 10% of their first purchase!
            </p>
            
            <div className="flex gap-3 max-w-md mx-auto">
              <Input
                value={user?.referralCode || ""}
                readOnly
                className="text-center text-2xl font-bold bg-background/50 border-gold/20"
                data-testid="input-referral-code"
              />
              <Button
                onClick={copyReferralCode}
                className="bg-gold hover:bg-gold/90 text-gold-foreground px-8"
                data-testid="button-copy-referral"
              >
                {copied ? <CheckCircle2 className="w-5 h-5" /> : <Copy className="w-5 h-5" />}
              </Button>
            </div>

            <div className="flex flex-wrap gap-3 justify-center pt-4">
              <Button
                variant="outline"
                className="border-primary/20"
                onClick={() => {
                  const text = `Join DataHub and get instant data bundles! Use my referral code: ${user?.referralCode}`;
                  window.open(`https://wa.me/?text=${encodeURIComponent(text)}`, "_blank");
                }}
                data-testid="button-share-whatsapp"
              >
                Share on WhatsApp
              </Button>
              <Button
                variant="outline"
                className="border-primary/20"
                onClick={() => {
                  const text = `Join DataHub and get instant data bundles! Use my referral code: ${user?.referralCode}`;
                  window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}`, "_blank");
                }}
                data-testid="button-share-twitter"
              >
                Share on Twitter
              </Button>
            </div>
          </div>
        </GlassCard>

        {/* How It Works */}
        <GlassCard glowColor="cyan" className="p-8">
          <h2 className="text-xl font-bold mb-6">How It Works</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center space-y-3">
              <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-primary/20 text-2xl font-bold">
                1
              </div>
              <h3 className="font-semibold">Share Your Link</h3>
              <p className="text-sm text-muted-foreground">
                Send your unique referral code to friends and family
              </p>
            </div>
            <div className="text-center space-y-3">
              <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-primary/20 text-2xl font-bold">
                2
              </div>
              <h3 className="font-semibold">They Sign Up</h3>
              <p className="text-sm text-muted-foreground">
                Your friend creates an account using your referral code
              </p>
            </div>
            <div className="text-center space-y-3">
              <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-primary/20 text-2xl font-bold">
                3
              </div>
              <h3 className="font-semibold">Earn Credits</h3>
              <p className="text-sm text-muted-foreground">
                Get GH₵5 instantly + 10% of their first purchase
              </p>
            </div>
          </div>
        </GlassCard>

        {/* Referral List */}
        <GlassCard glowColor="cyan" className="p-6">
          <h2 className="text-xl font-bold mb-6">Your Referrals</h2>
          
          {referralList.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Users className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No referrals yet. Start sharing your code!</p>
            </div>
          ) : (
            <div className="space-y-3">
              {referralList.map((referral) => (
                <div
                  key={referral.id}
                  className="flex items-center justify-between p-4 rounded-lg border border-border/50 hover-elevate"
                  data-testid={`referral-${referral.id}`}
                >
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-neon-cyan to-neon-magenta flex items-center justify-center">
                      <Users className="w-5 h-5" />
                    </div>
                    <div>
                      <p className="font-semibold" data-testid={`referral-name-${referral.id}`}>
                        {referral.referredName}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        Joined {new Date(referral.signupDate).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <Badge
                      className={
                        referral.status === "completed"
                          ? "bg-neon-green/20 text-neon-green border-neon-green/30"
                          : "bg-gold/20 text-gold border-gold/30"
                      }
                      data-testid={`referral-status-${referral.id}`}
                    >
                      {referral.status}
                    </Badge>
                    <p className="text-sm font-bold text-gold mt-2" data-testid={`referral-earned-${referral.id}`}>
                      +GH₵ {referral.earnedAmount}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </GlassCard>
      </div>
    </div>
  );
}
