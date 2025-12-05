import { useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useQuery } from "@tanstack/react-query";
import { StatCard } from "@/components/stat-card";
import { GlassCard } from "@/components/glass-card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Wallet, ShoppingBag, TrendingUp, Bell, ExternalLink } from "lucide-react";
import { Link } from "wouter";
import type { Order, WalletBalance } from "@shared/schema";

export default function CustomerDashboard() {
  const { toast } = useToast();
  const { user, isAuthenticated, isLoading } = useAuth();

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

  const { data: walletData } = useQuery<WalletBalance>({
    queryKey: ["/api/wallet/balance"],
    enabled: isAuthenticated,
  });

  const { data: recentOrders = [] } = useQuery<Order[]>({
    queryKey: ["/api/orders/recent"],
    enabled: isAuthenticated,
  });

  const { data: stats } = useQuery<{
    totalOrders: number;
    totalSpent: string;
    successRate: string;
  }>({
    queryKey: ["/api/stats/customer"],
    enabled: isAuthenticated,
  });

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading...</div>
      </div>
    );
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed": return "bg-neon-green/20 text-neon-green border-neon-green/30";
      case "processing": return "bg-primary/20 text-primary border-primary/30";
      case "pending": return "bg-gold/20 text-gold border-gold/30";
      case "failed": return "bg-destructive/20 text-destructive border-destructive/30";
      default: return "";
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-7xl mx-auto p-4 sm:p-6 lg:p-8 space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold mb-2">
              Welcome back, {user?.firstName || "Customer"}
            </h1>
            <p className="text-muted-foreground">Here's what's happening with your account</p>
          </div>
          <Button 
            className="bg-gold hover:bg-gold/90 text-gold-foreground"
            data-testid="button-buy-data"
            asChild
          >
            <Link href="/marketplace">
              <ShoppingBag className="w-4 h-4 mr-2" />
              Buy Data
            </Link>
          </Button>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatCard
            title="Wallet Balance"
            value={`GH₵ ${walletData?.balance || "0.00"}`}
            icon={Wallet}
            glowColor="gold"
          />
          <StatCard
            title="Total Orders"
            value={stats?.totalOrders || 0}
            icon={ShoppingBag}
            glowColor="cyan"
            change="+12% this month"
            trend="up"
          />
          <StatCard
            title="Total Spent"
            value={`GH₵ ${stats?.totalSpent || "0.00"}`}
            icon={TrendingUp}
            glowColor="magenta"
          />
          <StatCard
            title="Success Rate"
            value={stats?.successRate || "100%"}
            icon={Bell}
            glowColor="cyan"
            trend="up"
          />
        </div>

        {/* Quick Actions */}
        <GlassCard glowColor="cyan" className="p-6">
          <h2 className="text-xl font-bold mb-4">Quick Actions</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Button 
              variant="outline" 
              className="justify-start h-auto py-4 border-primary/20 hover:bg-primary/10"
              data-testid="button-marketplace"
              asChild
            >
              <Link href="/marketplace">
                <ShoppingBag className="w-5 h-5 mr-3" />
                <div className="text-left">
                  <div className="font-semibold">Browse Bundles</div>
                  <div className="text-xs text-muted-foreground">MTN, Vodafone, & more</div>
                </div>
              </Link>
            </Button>
            <Button 
              variant="outline" 
              className="justify-start h-auto py-4 border-primary/20 hover:bg-primary/10"
              data-testid="button-wallet"
              asChild
            >
              <Link href="/wallet">
                <Wallet className="w-5 h-5 mr-3" />
                <div className="text-left">
                  <div className="font-semibold">Top Up Wallet</div>
                  <div className="text-xs text-muted-foreground">Mobile Money</div>
                </div>
              </Link>
            </Button>
            <Button 
              variant="outline" 
              className="justify-start h-auto py-4 border-primary/20 hover:bg-primary/10"
              data-testid="button-referrals"
              asChild
            >
              <Link href="/referrals">
                <TrendingUp className="w-5 h-5 mr-3" />
                <div className="text-left">
                  <div className="font-semibold">Referral Program</div>
                  <div className="text-xs text-muted-foreground">Earn credits</div>
                </div>
              </Link>
            </Button>
            <Button 
              variant="outline" 
              className="justify-start h-auto py-4 border-primary/20 hover:bg-primary/10"
              data-testid="button-transactions"
              asChild
            >
              <Link href="/transactions">
                <ExternalLink className="w-5 h-5 mr-3" />
                <div className="text-left">
                  <div className="font-semibold">View History</div>
                  <div className="text-xs text-muted-foreground">All transactions</div>
                </div>
              </Link>
            </Button>
          </div>
        </GlassCard>

        {/* Recent Orders */}
        <GlassCard glowColor="cyan" className="p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold">Recent Orders</h2>
            <Button variant="ghost" size="sm" asChild data-testid="button-view-all-orders">
              <Link href="/orders">View All</Link>
            </Button>
          </div>
          
          {recentOrders.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <ShoppingBag className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No orders yet. Start by purchasing your first bundle!</p>
              <Button className="mt-4 bg-gold hover:bg-gold/90 text-gold-foreground" asChild data-testid="button-browse-bundles">
                <Link href="/marketplace">Browse Bundles</Link>
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {recentOrders.slice(0, 5).map((order) => (
                <div
                  key={order.id}
                  className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-lg border border-border/50 hover-elevate gap-3"
                  data-testid={`order-${order.id}`}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-2 flex-wrap">
                      <span className="font-semibold" data-testid={`order-provider-${order.id}`}>
                        {order.provider.toUpperCase()}
                      </span>
                      <Badge className={getStatusColor(order.status)} data-testid={`order-status-${order.id}`}>
                        {order.status}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground truncate" data-testid={`order-phone-${order.id}`}>
                      {order.recipientPhone}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      {order.createdAt ? new Date(order.createdAt).toLocaleString() : "N/A"}
                    </p>
                  </div>
                  <div className="flex items-center justify-between sm:flex-col sm:items-end gap-2">
                    <p className="font-bold text-lg" data-testid={`order-amount-${order.id}`}>
                      GH₵ {order.amount}
                    </p>
                    <Button 
                      variant="ghost" 
                      size="sm" 
                      className="text-primary"
                      data-testid={`button-view-order-${order.id}`}
                      asChild
                    >
                      <Link href={`/orders/${order.id}`}>View Details</Link>
                    </Button>
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
