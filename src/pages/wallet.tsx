import { useState, useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useQuery } from "@tanstack/react-query";
import { GlassCard } from "@/components/glass-card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Wallet as WalletIcon, Plus, ArrowDownLeft, ArrowUpRight, CheckCircle2, Smartphone } from "lucide-react";
import type { WalletBalance, Transaction } from "@shared/schema";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { isUnauthorizedError } from "@/lib/authUtils";

type PaymentProvider = "mtn_momo" | "vodafone_cash" | "airteltigo_money";

export default function Wallet() {
  const { toast } = useToast();
  const { user, isAuthenticated, isLoading } = useAuth();
  const [isTopUpOpen, setIsTopUpOpen] = useState(false);
  const [topUpAmount, setTopUpAmount] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [selectedProvider, setSelectedProvider] = useState<PaymentProvider>("mtn_momo");
  const [isProcessing, setIsProcessing] = useState(false);
  const [processingStep, setProcessingStep] = useState(0);

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

  const { data: transactions = [] } = useQuery<Transaction[]>({
    queryKey: ["/api/wallet/transactions"],
    enabled: isAuthenticated,
  });

  const providerNames: Record<PaymentProvider, string> = {
    mtn_momo: "MTN Mobile Money",
    vodafone_cash: "Vodafone Cash",
    airteltigo_money: "AirtelTigo Money",
  };

  const initializePayment = async () => {
    if (!topUpAmount || parseFloat(topUpAmount) < 1) {
      toast({
        title: "Invalid Amount",
        description: "Please enter an amount of at least GH₵ 1",
        variant: "destructive",
      });
      return;
    }

    if (!phoneNumber || phoneNumber.length < 10) {
      toast({
        title: "Invalid Phone Number",
        description: "Please enter a valid phone number",
        variant: "destructive",
      });
      return;
    }

    setIsProcessing(true);
    setProcessingStep(1);

    try {
      await new Promise(resolve => setTimeout(resolve, 1500));
      setProcessingStep(2);
      
      await new Promise(resolve => setTimeout(resolve, 1500));
      setProcessingStep(3);

      const response = await apiRequest("POST", "/api/wallet/topup", {
        amount: topUpAmount,
        provider: selectedProvider,
        phoneNumber: phoneNumber,
      });
      const data = await response.json();

      if (data.success) {
        setProcessingStep(4);
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        toast({
          title: "Top-up Successful!",
          description: `GH₵ ${topUpAmount} has been added to your wallet`,
        });
        queryClient.invalidateQueries({ queryKey: ["/api/wallet/balance"] });
        queryClient.invalidateQueries({ queryKey: ["/api/wallet/transactions"] });
        setIsTopUpOpen(false);
        setTopUpAmount("");
        setPhoneNumber("");
      } else {
        throw new Error(data.message || "Failed to process payment");
      }
    } catch (error: any) {
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
        title: "Payment Failed",
        description: error.message || "Please try again",
        variant: "destructive",
      });
    } finally {
      setIsProcessing(false);
      setProcessingStep(0);
    }
  };

  const getTransactionIcon = (type: string) => {
    switch (type) {
      case "topup": return <Plus className="w-5 h-5 text-neon-green" />;
      case "purchase": return <ArrowUpRight className="w-5 h-5 text-destructive" />;
      case "withdrawal": return <ArrowDownLeft className="w-5 h-5 text-gold" />;
      case "refund": return <ArrowDownLeft className="w-5 h-5 text-neon-green" />;
      case "commission": return <Plus className="w-5 h-5 text-gold" />;
      case "referral_bonus": return <Plus className="w-5 h-5 text-neon-cyan" />;
      default: return <WalletIcon className="w-5 h-5" />;
    }
  };

  const getTransactionColor = (type: string) => {
    return ["topup", "refund", "commission", "referral_bonus"].includes(type) 
      ? "text-neon-green" 
      : "text-destructive";
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading wallet...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-7xl mx-auto p-4 sm:p-6 lg:p-8 space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold mb-2">Wallet</h1>
          <p className="text-muted-foreground">Manage your balance and transactions</p>
        </div>

        {/* Balance Card */}
        <GlassCard glowColor="gold" className="p-8 text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gold/20 mb-4">
            <WalletIcon className="w-8 h-8 text-gold" />
          </div>
          <p className="text-sm text-muted-foreground mb-2">Available Balance</p>
          <p className="text-5xl font-bold mb-6" data-testid="wallet-balance">
            GH₵ {walletData?.balance || "0.00"}
          </p>
          <Button
            onClick={() => setIsTopUpOpen(true)}
            className="bg-gold hover:bg-gold/90 text-gold-foreground font-semibold px-8"
            data-testid="button-topup-wallet"
          >
            <Plus className="w-5 h-5 mr-2" />
            Top Up Wallet
          </Button>
        </GlassCard>

        {/* Transactions */}
        <GlassCard glowColor="cyan" className="p-6">
          <h2 className="text-xl font-bold mb-6">Transaction History</h2>
          
          {transactions.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <WalletIcon className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No transactions yet</p>
            </div>
          ) : (
            <div className="space-y-3">
              {transactions.slice(0, 20).map((txn) => (
                <div
                  key={txn.id}
                  className="flex items-center justify-between p-4 rounded-lg border border-border/50 hover-elevate"
                  data-testid={`transaction-${txn.id}`}
                >
                  <div className="flex items-center gap-4">
                    <div className="p-2 rounded-lg bg-background/50">
                      {getTransactionIcon(txn.type)}
                    </div>
                    <div>
                      <p className="font-semibold capitalize" data-testid={`transaction-type-${txn.id}`}>
                        {txn.type.replace("_", " ")}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {txn.createdAt ? new Date(txn.createdAt).toLocaleString() : "N/A"}
                      </p>
                      {txn.description && (
                        <p className="text-xs text-muted-foreground mt-1">{txn.description}</p>
                      )}
                    </div>
                  </div>
                  <div className="text-right">
                    <p className={`text-lg font-bold ${getTransactionColor(txn.type)}`} data-testid={`transaction-amount-${txn.id}`}>
                      {["topup", "refund", "commission", "referral_bonus"].includes(txn.type) ? "+" : "-"}
                      GH₵ {txn.amount}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Balance: GH₵ {txn.balanceAfter}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </GlassCard>
      </div>

      {/* Top-up Dialog */}
      <Dialog open={isTopUpOpen} onOpenChange={(open) => {
        if (!isProcessing) {
          setIsTopUpOpen(open);
          if (!open) {
            setTopUpAmount("");
            setPhoneNumber("");
          }
        }
      }}>
        <DialogContent className="bg-card border-primary/20">
          <DialogHeader>
            <DialogTitle>Top Up Your Wallet</DialogTitle>
            <DialogDescription>
              Add funds using Mobile Money
            </DialogDescription>
          </DialogHeader>

          {isProcessing ? (
            <div className="py-8 text-center space-y-6">
              <div className="relative w-20 h-20 mx-auto">
                <div className="absolute inset-0 border-4 border-neon-cyan/20 rounded-full" />
                <div className="absolute inset-0 border-4 border-neon-cyan border-t-transparent rounded-full animate-spin" />
                <div className="absolute inset-0 flex items-center justify-center">
                  {processingStep >= 4 ? (
                    <CheckCircle2 className="w-8 h-8 text-neon-green" />
                  ) : (
                    <Smartphone className="w-8 h-8 text-neon-cyan" />
                  )}
                </div>
              </div>
              
              <div className="space-y-2">
                <p className="font-semibold text-lg">
                  {processingStep === 1 && "Connecting to " + providerNames[selectedProvider] + "..."}
                  {processingStep === 2 && "Processing payment..."}
                  {processingStep === 3 && "Confirming transaction..."}
                  {processingStep === 4 && "Payment Successful!"}
                </p>
                <p className="text-sm text-muted-foreground">
                  {processingStep < 4 ? "Please wait, do not close this window" : "Updating your wallet balance..."}
                </p>
              </div>

              <div className="flex justify-center gap-2">
                {[1, 2, 3, 4].map((step) => (
                  <div
                    key={step}
                    className={`w-2 h-2 rounded-full transition-all duration-300 ${
                      processingStep >= step ? "bg-neon-cyan w-4" : "bg-muted"
                    }`}
                  />
                ))}
              </div>
            </div>
          ) : (
            <div className="space-y-6 mt-4">
              {/* Provider Selection */}
              <div className="space-y-3">
                <Label>Select Payment Method</Label>
                <div className="grid grid-cols-1 gap-2">
                  {(["mtn_momo", "vodafone_cash", "airteltigo_money"] as PaymentProvider[]).map((provider) => (
                    <button
                      key={provider}
                      onClick={() => setSelectedProvider(provider)}
                      className={`p-4 rounded-lg border text-left transition-all ${
                        selectedProvider === provider
                          ? "border-neon-cyan bg-neon-cyan/10"
                          : "border-border hover:border-neon-cyan/50"
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                          provider === "mtn_momo" ? "bg-yellow-500/20" :
                          provider === "vodafone_cash" ? "bg-red-500/20" : "bg-blue-500/20"
                        }`}>
                          <Smartphone className={`w-5 h-5 ${
                            provider === "mtn_momo" ? "text-yellow-500" :
                            provider === "vodafone_cash" ? "text-red-500" : "text-blue-500"
                          }`} />
                        </div>
                        <span className="font-medium">{providerNames[provider]}</span>
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Phone Number */}
              <div className="space-y-2">
                <Label htmlFor="phone">Phone Number</Label>
                <Input
                  id="phone"
                  type="tel"
                  placeholder="0241234567"
                  value={phoneNumber}
                  onChange={(e) => setPhoneNumber(e.target.value)}
                  className="bg-background/50"
                  data-testid="input-phone-number"
                />
              </div>

              {/* Amount */}
              <div className="space-y-2">
                <Label htmlFor="amount">Amount (GH₵)</Label>
                <Input
                  id="amount"
                  type="number"
                  min="1"
                  step="0.01"
                  placeholder="Enter amount"
                  value={topUpAmount}
                  onChange={(e) => setTopUpAmount(e.target.value)}
                  className="bg-background/50 text-lg"
                  data-testid="input-topup-amount"
                />
              </div>

              {/* Quick Amount Buttons */}
              <div className="grid grid-cols-4 gap-2">
                {[10, 20, 50, 100].map((amount) => (
                  <Button
                    key={amount}
                    variant="outline"
                    size="sm"
                    onClick={() => setTopUpAmount(amount.toString())}
                    className={topUpAmount === amount.toString() ? "border-neon-cyan bg-neon-cyan/10" : ""}
                  >
                    GH₵{amount}
                  </Button>
                ))}
              </div>

              <div className="flex gap-3">
                <Button
                  variant="outline"
                  onClick={() => {
                    setIsTopUpOpen(false);
                    setTopUpAmount("");
                    setPhoneNumber("");
                  }}
                  className="flex-1"
                  data-testid="button-cancel-topup"
                >
                  Cancel
                </Button>
                <Button
                  onClick={initializePayment}
                  disabled={!topUpAmount || parseFloat(topUpAmount) < 1 || !phoneNumber}
                  className="flex-1 bg-neon-cyan hover:bg-neon-cyan/90 text-background font-semibold"
                  data-testid="button-confirm-topup"
                >
                  <Smartphone className="w-4 h-4 mr-2" />
                  Pay GH₵{topUpAmount || "0"}
                </Button>
              </div>

              <p className="text-xs text-center text-muted-foreground">
                Secure mobile money payment. Your transaction is protected.
              </p>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
