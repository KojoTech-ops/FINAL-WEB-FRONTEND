import { useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useQuery } from "@tanstack/react-query";
import { useParams, Link } from "wouter";
import { GlassCard } from "@/components/glass-card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, Phone, Clock, CheckCircle2, XCircle, Loader2, Package } from "lucide-react";
import type { Order, Bundle } from "@shared/schema";

export default function OrderDetails() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const params = useParams<{ id: string }>();
  const orderId = params.id;

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      toast({
        title: "Unauthorized",
        description: "You are logged out. Logging in again...",
        variant: "destructive",
      });
      setTimeout(() => {
        window.location.href = "/api/login";
      }, 500);
    }
  }, [isAuthenticated, authLoading, toast]);

  const { data: order, isLoading: orderLoading } = useQuery<Order>({
    queryKey: [`/api/orders/${orderId}`],
    enabled: isAuthenticated && !!orderId,
  });

  const { data: bundle } = useQuery<Bundle>({
    queryKey: [`/api/bundles/${order?.bundleId}`],
    enabled: isAuthenticated && !!order?.bundleId,
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <CheckCircle2 className="w-8 h-8 text-neon-green" />;
      case "processing":
        return <Loader2 className="w-8 h-8 text-primary animate-spin" />;
      case "pending":
        return <Clock className="w-8 h-8 text-gold" />;
      case "failed":
        return <XCircle className="w-8 h-8 text-destructive" />;
      default:
        return <Package className="w-8 h-8" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "bg-neon-green/20 text-neon-green border-neon-green/30";
      case "processing":
        return "bg-primary/20 text-primary border-primary/30";
      case "pending":
        return "bg-gold/20 text-gold border-gold/30";
      case "failed":
        return "bg-destructive/20 text-destructive border-destructive/30";
      default:
        return "";
    }
  };

  const getStatusMessage = (status: string) => {
    switch (status) {
      case "completed":
        return "Your data bundle has been successfully delivered!";
      case "processing":
        return "Your order is being processed. This usually takes less than 30 seconds.";
      case "pending":
        return "Your order is waiting to be processed.";
      case "failed":
        return "Unfortunately, this order could not be completed. Your wallet has not been charged.";
      default:
        return "";
    }
  };

  if (authLoading || orderLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading order details...</div>
      </div>
    );
  }

  if (!order) {
    return (
      <div className="min-h-screen bg-background">
        <div className="max-w-3xl mx-auto p-4 sm:p-6 lg:p-8">
          <GlassCard className="p-8 text-center">
            <Package className="w-16 h-16 mx-auto mb-4 text-muted-foreground opacity-50" />
            <h2 className="text-2xl font-bold mb-2">Order Not Found</h2>
            <p className="text-muted-foreground mb-6">
              This order doesn't exist or you don't have permission to view it.
            </p>
            <Button asChild>
              <Link href="/dashboard">Back to Dashboard</Link>
            </Button>
          </GlassCard>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-3xl mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        <Button variant="ghost" asChild className="mb-4">
          <Link href="/dashboard">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Dashboard
          </Link>
        </Button>

        <GlassCard glowColor="cyan" className="p-8">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-background/50 mb-4">
              {getStatusIcon(order.status)}
            </div>
            <Badge className={`${getStatusColor(order.status)} text-lg px-4 py-1`}>
              {order.status.charAt(0).toUpperCase() + order.status.slice(1)}
            </Badge>
            <p className="text-muted-foreground mt-4 max-w-md mx-auto">
              {getStatusMessage(order.status)}
            </p>
          </div>

          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="p-4 rounded-lg bg-background/50 border border-border/50">
                <p className="text-sm text-muted-foreground mb-1">Order ID</p>
                <p className="font-mono text-sm">{order.id}</p>
              </div>
              <div className="p-4 rounded-lg bg-background/50 border border-border/50">
                <p className="text-sm text-muted-foreground mb-1">Date & Time</p>
                <p className="font-semibold">
                  {order.createdAt ? new Date(order.createdAt).toLocaleString() : "N/A"}
                </p>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-background/50 border border-border/50">
              <p className="text-sm text-muted-foreground mb-1">Recipient Phone Number</p>
              <div className="flex items-center gap-2">
                <Phone className="w-5 h-5 text-primary" />
                <p className="text-xl font-semibold">{order.recipientPhone}</p>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-background/50 border border-border/50">
              <p className="text-sm text-muted-foreground mb-1">Bundle Details</p>
              <div className="flex items-center justify-between">
                <div>
                  <Badge className="mb-2">
                    {order.provider.toUpperCase()}
                  </Badge>
                  <p className="text-xl font-semibold">
                    {bundle?.dataSize || "Data Bundle"}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {bundle?.name || ""}
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-3xl font-bold text-gold">
                    GH₵ {order.amount}
                  </p>
                </div>
              </div>
            </div>

            {order.errorMessage && (
              <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/30">
                <p className="text-sm text-destructive font-semibold mb-1">Error Message</p>
                <p className="text-destructive">{order.errorMessage}</p>
              </div>
            )}
          </div>
        </GlassCard>

        <div className="flex gap-4">
          <Button variant="outline" className="flex-1" asChild>
            <Link href="/transactions">View Transactions</Link>
          </Button>
          <Button className="flex-1 bg-gold hover:bg-gold/90 text-gold-foreground" asChild>
            <Link href="/marketplace">Buy More Data</Link>
          </Button>
        </div>
      </div>
    </div>
  );
}
