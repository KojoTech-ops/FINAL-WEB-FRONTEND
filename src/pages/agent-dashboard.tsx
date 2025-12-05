import { useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useQuery } from "@tanstack/react-query";
import { StatCard } from "@/components/stat-card";
import { GlassCard } from "@/components/glass-card";
import { Button } from "@/components/ui/button";
import { DollarSign, TrendingUp, Users, Award, Download } from "lucide-react";
import { Link } from "wouter";
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from "recharts";

export default function AgentDashboard() {
  const { toast } = useToast();
  const { user, isAuthenticated, isLoading, isAgent } = useAuth();

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

  const { data: stats } = useQuery<{
    totalCommissions: string;
    pendingPayouts: string;
    totalSales: number;
    conversionRate: string;
  }>({
    queryKey: ["/api/stats/agent"],
    enabled: isAuthenticated && isAgent,
  });

  const { data: salesData = [] } = useQuery<Array<{ date: string; sales: number; commissions: number }>>({
    queryKey: ["/api/analytics/sales"],
    enabled: isAuthenticated && isAgent,
  });

  const { data: topCustomers = [] } = useQuery<Array<{ id: string; name: string; totalSpent: string; orders: number }>>({
    queryKey: ["/api/analytics/top-customers"],
    enabled: isAuthenticated && isAgent,
  });

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading...</div>
      </div>
    );
  }

  if (!isAgent) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <GlassCard glowColor="magenta" className="p-8 text-center max-w-md">
          <h2 className="text-2xl font-bold mb-4">Agent Access Required</h2>
          <p className="text-muted-foreground mb-6">
            This page is only accessible to agent accounts. Contact support to upgrade your account.
          </p>
          <Button asChild>
            <Link href="/dashboard">Go to Dashboard</Link>
          </Button>
        </GlassCard>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-7xl mx-auto p-4 sm:p-6 lg:p-8 space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold mb-2">Agent Dashboard</h1>
            <p className="text-muted-foreground">Track your sales, commissions, and performance</p>
          </div>
          <div className="flex gap-3">
            <Button 
              variant="outline" 
              className="border-primary/20"
              data-testid="button-download-report"
            >
              <Download className="w-4 h-4 mr-2" />
              Download Report
            </Button>
            <Button 
              className="bg-gold hover:bg-gold/90 text-gold-foreground"
              data-testid="button-request-payout"
            >
              Request Payout
            </Button>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatCard
            title="Total Commissions"
            value={`GH₵ ${stats?.totalCommissions || "0.00"}`}
            icon={DollarSign}
            glowColor="gold"
            change="+18% this month"
            trend="up"
          />
          <StatCard
            title="Pending Payouts"
            value={`GH₵ ${stats?.pendingPayouts || "0.00"}`}
            icon={Award}
            glowColor="cyan"
          />
          <StatCard
            title="Total Sales"
            value={stats?.totalSales || 0}
            icon={TrendingUp}
            glowColor="magenta"
            change="+24 this week"
            trend="up"
          />
          <StatCard
            title="Conversion Rate"
            value={stats?.conversionRate || "0%"}
            icon={Users}
            glowColor="cyan"
            change="+5% improvement"
            trend="up"
          />
        </div>

        {/* Sales Chart */}
        <GlassCard glowColor="cyan" className="p-6">
          <h2 className="text-xl font-bold mb-6">Sales & Commissions</h2>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={salesData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis 
                  dataKey="date" 
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: '12px' }}
                />
                <YAxis 
                  stroke="hsl(var(--muted-foreground))"
                  style={{ fontSize: '12px' }}
                />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '8px',
                  }}
                />
                <Line 
                  type="monotone" 
                  dataKey="sales" 
                  stroke="hsl(var(--neon-cyan))" 
                  strokeWidth={2}
                  dot={{ fill: 'hsl(var(--neon-cyan))' }}
                />
                <Line 
                  type="monotone" 
                  dataKey="commissions" 
                  stroke="hsl(var(--gold))" 
                  strokeWidth={2}
                  dot={{ fill: 'hsl(var(--gold))' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </GlassCard>

        {/* Top Customers */}
        <GlassCard glowColor="cyan" className="p-6">
          <h2 className="text-xl font-bold mb-6">Top Customers</h2>
          {topCustomers.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Users className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No customer data available yet</p>
            </div>
          ) : (
            <div className="space-y-4">
              {topCustomers.map((customer, idx) => (
                <div
                  key={customer.id}
                  className="flex items-center justify-between p-4 rounded-lg border border-border/50 hover-elevate"
                  data-testid={`customer-${customer.id}`}
                >
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-neon-cyan to-neon-magenta flex items-center justify-center font-bold">
                      #{idx + 1}
                    </div>
                    <div>
                      <p className="font-semibold" data-testid={`customer-name-${customer.id}`}>{customer.name}</p>
                      <p className="text-sm text-muted-foreground">{customer.orders} orders</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="font-bold text-lg" data-testid={`customer-spent-${customer.id}`}>
                      GH₵ {customer.totalSpent}
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
