import { useState, useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useQuery, useMutation } from "@tanstack/react-query";
import { GlassCard } from "@/components/glass-card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Slider } from "@/components/ui/slider";
import { Search, Filter, Clock, Zap } from "lucide-react";
import type { Bundle } from "@shared/schema";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { isUnauthorizedError } from "@/lib/authUtils";

export default function Marketplace() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedProvider, setSelectedProvider] = useState<string>("all");
  const [priceRange, setPriceRange] = useState([0, 500]);
  const [selectedBundle, setSelectedBundle] = useState<Bundle | null>(null);
  const [recipientPhone, setRecipientPhone] = useState("");
  const [isPurchasing, setIsPurchasing] = useState(false);

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

  const { data: bundles = [], isLoading: bundlesLoading } = useQuery<Bundle[]>({
    queryKey: ["/api/bundles"],
    enabled: isAuthenticated,
  });

  const purchaseMutation = useMutation({
    mutationFn: async (data: { bundleId: string; recipientPhone: string }) => {
      return await apiRequest("POST", "/api/orders", data);
    },
    onSuccess: () => {
      toast({
        title: "Order Placed Successfully!",
        description: "Your data bundle is being processed",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/orders"] });
      queryClient.invalidateQueries({ queryKey: ["/api/wallet/balance"] });
      setIsPurchasing(false);
      setSelectedBundle(null);
      setRecipientPhone("");
    },
    onError: (error: Error) => {
      if (isUnauthorizedError(error)) {
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
      toast({
        title: "Purchase Failed",
        description: error.message || "Please try again",
        variant: "destructive",
      });
    },
  });

  const filteredBundles = bundles.filter(bundle => {
    const matchesSearch = bundle.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          bundle.dataSize.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesProvider = selectedProvider === "all" || bundle.provider === selectedProvider;
    const matchesPrice = parseFloat(bundle.price) >= priceRange[0] && parseFloat(bundle.price) <= priceRange[1];
    return matchesSearch && matchesProvider && matchesPrice && bundle.isActive;
  });

  const handlePurchase = () => {
    if (!selectedBundle || !recipientPhone) return;
    purchaseMutation.mutate({
      bundleId: selectedBundle.id,
      recipientPhone,
    });
  };

  const getProviderColor = (provider: string) => {
    switch (provider) {
      case "mtn": return "bg-gold/20 text-gold border-gold/30";
      case "vodafone": return "bg-destructive/20 text-destructive border-destructive/30";
      case "airteltigo": return "bg-neon-cyan/20 text-neon-cyan border-neon-cyan/30";
      case "international": return "bg-neon-magenta/20 text-neon-magenta border-neon-magenta/30";
      default: return "";
    }
  };

  if (isLoading || bundlesLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading marketplace...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-7xl mx-auto p-4 sm:p-6 lg:p-8 space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold mb-2">Data Marketplace</h1>
          <p className="text-muted-foreground">Browse and purchase data bundles instantly</p>
        </div>

        {/* Search & Filters */}
        <GlassCard glowColor="cyan" className="p-6">
          <div className="space-y-6">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                placeholder="Search bundles..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 bg-background/50 border-primary/20"
                data-testid="input-search-bundles"
              />
            </div>

            {/* Provider Tabs */}
            <Tabs value={selectedProvider} onValueChange={setSelectedProvider}>
              <TabsList className="grid grid-cols-3 sm:grid-cols-5 w-full bg-background/50 h-auto gap-1">
                <TabsTrigger value="all" data-testid="tab-all" className="text-xs sm:text-sm px-2">All</TabsTrigger>
                <TabsTrigger value="mtn" data-testid="tab-mtn" className="text-xs sm:text-sm px-2">MTN</TabsTrigger>
                <TabsTrigger value="vodafone" data-testid="tab-vodafone" className="text-xs sm:text-sm px-2">Vodafone</TabsTrigger>
                <TabsTrigger value="airteltigo" data-testid="tab-airteltigo" className="text-xs sm:text-sm px-2">AirtelTigo</TabsTrigger>
                <TabsTrigger value="international" data-testid="tab-international" className="text-xs sm:text-sm px-2 col-span-3 sm:col-span-1">Int'l</TabsTrigger>
              </TabsList>
            </Tabs>

            {/* Price Range */}
            <div>
              <div className="flex items-center justify-between mb-4">
                <Label className="flex items-center gap-2">
                  <Filter className="w-4 h-4" />
                  Price Range
                </Label>
                <span className="text-sm text-muted-foreground">
                  GH₵ {priceRange[0]} - GH₵ {priceRange[1]}
                </span>
              </div>
              <Slider
                value={priceRange}
                onValueChange={setPriceRange}
                min={0}
                max={500}
                step={10}
                className="w-full"
              />
            </div>
          </div>
        </GlassCard>

        {/* Bundles Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredBundles.map((bundle) => (
            <GlassCard
              key={bundle.id}
              glowColor="cyan"
              className="p-6 hover:scale-105 transition-transform cursor-pointer"
              data-testid={`bundle-card-${bundle.id}`}
            >
              <div className="space-y-4">
                <div className="flex items-start justify-between">
                  <Badge className={getProviderColor(bundle.provider)} data-testid={`bundle-provider-${bundle.id}`}>
                    {bundle.provider.toUpperCase()}
                  </Badge>
                  <Badge variant="outline" className="border-neon-green/30 text-neon-green">
                    <Clock className="w-3 h-3 mr-1" />
                    {bundle.eta}
                  </Badge>
                </div>

                <div>
                  <h3 className="text-2xl font-bold mb-2" data-testid={`bundle-size-${bundle.id}`}>
                    {bundle.dataSize}
                  </h3>
                  <p className="text-sm text-muted-foreground" data-testid={`bundle-name-${bundle.id}`}>
                    {bundle.name}
                  </p>
                </div>

                <div className="flex items-end justify-between pt-4 border-t border-border/50">
                  <div>
                    <p className="text-3xl font-bold text-gold" data-testid={`bundle-price-${bundle.id}`}>
                      GH₵ {bundle.price}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">Retail Price</p>
                  </div>
                  <Button
                    size="sm"
                    onClick={() => {
                      setSelectedBundle(bundle);
                      setIsPurchasing(true);
                    }}
                    className="bg-primary hover:bg-primary/90"
                    data-testid={`button-buy-${bundle.id}`}
                  >
                    <Zap className="w-3 h-3 mr-1" />
                    Buy
                  </Button>
                </div>
              </div>
            </GlassCard>
          ))}
        </div>

        {filteredBundles.length === 0 && (
          <div className="text-center py-20">
            <p className="text-muted-foreground text-lg">No bundles found matching your criteria</p>
          </div>
        )}
      </div>

      {/* Purchase Dialog */}
      <Dialog open={isPurchasing} onOpenChange={setIsPurchasing}>
        <DialogContent className="bg-card border-primary/20">
          <DialogHeader>
            <DialogTitle>Complete Your Purchase</DialogTitle>
            <DialogDescription>
              Enter the recipient's phone number to receive the data bundle
            </DialogDescription>
          </DialogHeader>
          
          {selectedBundle && (
            <div className="space-y-6">
              <div className="p-4 rounded-lg bg-background/50 border border-border/50">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-muted-foreground">Bundle</span>
                  <Badge className={getProviderColor(selectedBundle.provider)}>
                    {selectedBundle.provider.toUpperCase()}
                  </Badge>
                </div>
                <p className="text-xl font-bold mb-1">{selectedBundle.dataSize}</p>
                <p className="text-2xl font-bold text-gold">GH₵ {selectedBundle.price}</p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="phone">Recipient Phone Number</Label>
                <Input
                  id="phone"
                  placeholder="0XX XXX XXXX"
                  value={recipientPhone}
                  onChange={(e) => setRecipientPhone(e.target.value)}
                  className="bg-background/50 border-primary/20"
                  data-testid="input-recipient-phone"
                />
              </div>

              <div className="flex gap-3">
                <Button
                  variant="outline"
                  onClick={() => {
                    setIsPurchasing(false);
                    setSelectedBundle(null);
                    setRecipientPhone("");
                  }}
                  className="flex-1"
                  data-testid="button-cancel-purchase"
                >
                  Cancel
                </Button>
                <Button
                  onClick={handlePurchase}
                  disabled={!recipientPhone || purchaseMutation.isPending}
                  className="flex-1 bg-gold hover:bg-gold/90 text-gold-foreground"
                  data-testid="button-confirm-purchase"
                >
                  {purchaseMutation.isPending ? "Processing..." : "Confirm Purchase"}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
