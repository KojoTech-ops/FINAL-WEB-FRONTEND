import { useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useQuery } from "@tanstack/react-query";
import { GlassCard } from "@/components/glass-card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ShoppingBag, ArrowLeft, Package, Clock, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { Link } from "wouter";
import type { Order } from "@shared/schema";

export default function Orders() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading: authLoading } = useAuth();

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
      return;
    }
  }, [isAuthenticated, authLoading, toast]);

  const { data: orders = [], isLoading } = useQuery<Order[]>({
    queryKey: ["/api/orders"],
    enabled: isAuthenticated,
  });

  if (authLoading) {
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

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed": return <CheckCircle2 className="w-4 h-4" />;
      case "processing": return <Loader2 className="w-4 h-4 animate-spin" />;
      case "pending": return <Clock className="w-4 h-4" />;
      case "failed": return <XCircle className="w-4 h-4" />;
      default: return <Package className="w-4 h-4" />;
    }
  };

  const getProviderColor = (provider: string) => {
    switch (provider.toLowerCase()) {
      case "mtn": return "text-yellow-400";
      case "vodafone": return "text-red-400";
      case "airteltigo": return "text-blue-400";
      case "international": return "text-purple-400";
      default: return "text-white";
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-7xl mx-auto p-4 sm:p-6 lg:p-8 space-y-8">
        {/* Header */}
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" asChild>
            <Link href="/dashboard">
              <ArrowLeft className="w-5 h-5" />
            </Link>
          </Button>
          <div>
            <h1 className="text-3xl font-bold mb-1">All Orders</h1>
            <p className="text-muted-foreground">View and manage all your data bundle orders</p>
          </div>
        </div>

        {/* Orders List */}
        <GlassCard glowColor="cyan" className="p-6">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : orders.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <ShoppingBag className="w-16 h-16 mx-auto mb-4 opacity-50" />
              <h3 className="text-lg font-semibold mb-2">No orders yet</h3>
              <p className="mb-4">Start by purchasing your first data bundle!</p>
              <Button className="bg-gold hover:bg-gold/90 text-gold-foreground" asChild>
                <Link href="/marketplace">Browse Bundles</Link>
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {orders.map((order) => (
                <div
                  key={order.id}
                  className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-lg border border-border/50 hover:bg-white/5 transition-colors gap-4"
                >
                  <div className="flex items-start gap-4 flex-1 min-w-0">
                    <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-neon-cyan/20 to-neon-magenta/20 flex items-center justify-center flex-shrink-0">
                      <Package className="w-6 h-6 text-primary" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 flex-wrap mb-1">
                        <span className={`font-bold ${getProviderColor(order.provider)}`}>
                          {order.provider.toUpperCase()}
                        </span>
                        <Badge className={`${getStatusColor(order.status)} flex items-center gap-1`}>
                          {getStatusIcon(order.status)}
                          <span className="capitalize">{order.status}</span>
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground truncate">
                        Recipient: {order.recipientPhone}
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {order.createdAt ? new Date(order.createdAt).toLocaleString() : "N/A"}
                      </p>
                      {order.errorMessage && (
                        <p className="text-xs text-destructive mt-1 truncate">
                          Error: {order.errorMessage}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center justify-between sm:justify-end gap-4 sm:flex-col sm:items-end">
                    <p className="font-bold text-lg text-gold">
                      GH₵ {order.amount}
                    </p>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="border-primary/30 hover:bg-primary/10"
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
