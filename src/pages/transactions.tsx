import { useEffect, useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useQuery } from "@tanstack/react-query";
import { GlassCard } from "@/components/glass-card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Download, Search, Filter, FileText } from "lucide-react";
import type { Transaction } from "@shared/schema";

export default function Transactions() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [sortOrder, setSortOrder] = useState("desc");

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

  const { data: transactions = [] } = useQuery<Transaction[]>({
    queryKey: ["/api/transactions"],
    enabled: isAuthenticated,
  });

  const handleExportCSV = () => {
    toast({
      title: "Exporting CSV",
      description: "Your transaction history is being exported",
    });
  };

  const handleExportPDF = () => {
    toast({
      title: "Exporting PDF",
      description: "Your transaction history is being exported",
    });
  };

  const filteredTransactions = transactions
    .filter(txn => {
      const matchesSearch = txn.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           txn.reference?.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesType = filterType === "all" || txn.type === filterType;
      return matchesSearch && matchesType;
    })
    .sort((a, b) => {
      const dateA = a.createdAt ? new Date(a.createdAt).getTime() : 0;
      const dateB = b.createdAt ? new Date(b.createdAt).getTime() : 0;
      return sortOrder === "desc" ? dateB - dateA : dateA - dateB;
    });

  const getTypeColor = (type: string) => {
    switch (type) {
      case "topup": return "bg-neon-green/20 text-neon-green border-neon-green/30";
      case "purchase": return "bg-destructive/20 text-destructive border-destructive/30";
      case "withdrawal": return "bg-gold/20 text-gold border-gold/30";
      case "refund": return "bg-neon-green/20 text-neon-green border-neon-green/30";
      case "commission": return "bg-gold/20 text-gold border-gold/30";
      case "referral_bonus": return "bg-primary/20 text-primary border-primary/30";
      default: return "";
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading transactions...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-7xl mx-auto p-4 sm:p-6 lg:p-8 space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold mb-2">Transaction History</h1>
            <p className="text-muted-foreground">View and export all your transactions</p>
          </div>
          <div className="flex gap-3">
            <Button
              variant="outline"
              onClick={handleExportCSV}
              className="border-primary/20"
              data-testid="button-export-csv"
            >
              <Download className="w-4 h-4 mr-2" />
              Export CSV
            </Button>
            <Button
              variant="outline"
              onClick={handleExportPDF}
              className="border-primary/20"
              data-testid="button-export-pdf"
            >
              <FileText className="w-4 h-4 mr-2" />
              Export PDF
            </Button>
          </div>
        </div>

        {/* Filters */}
        <GlassCard glowColor="cyan" className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                placeholder="Search transactions..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 bg-background/50 border-primary/20"
                data-testid="input-search-transactions"
              />
            </div>

            <Select value={filterType} onValueChange={setFilterType}>
              <SelectTrigger className="bg-background/50 border-primary/20" data-testid="select-filter-type">
                <SelectValue placeholder="Filter by type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="topup">Top Up</SelectItem>
                <SelectItem value="purchase">Purchase</SelectItem>
                <SelectItem value="withdrawal">Withdrawal</SelectItem>
                <SelectItem value="refund">Refund</SelectItem>
                <SelectItem value="commission">Commission</SelectItem>
                <SelectItem value="referral_bonus">Referral Bonus</SelectItem>
              </SelectContent>
            </Select>

            <Select value={sortOrder} onValueChange={setSortOrder}>
              <SelectTrigger className="bg-background/50 border-primary/20" data-testid="select-sort-order">
                <SelectValue placeholder="Sort order" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="desc">Newest First</SelectItem>
                <SelectItem value="asc">Oldest First</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </GlassCard>

        {/* Transactions Table */}
        <GlassCard glowColor="cyan" className="p-6">
          {filteredTransactions.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No transactions found</p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredTransactions.map((txn) => (
                <div
                  key={txn.id}
                  className="flex items-center justify-between p-4 rounded-lg border border-border/50 hover-elevate"
                  data-testid={`transaction-${txn.id}`}
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <Badge className={getTypeColor(txn.type)} data-testid={`transaction-type-${txn.id}`}>
                        {txn.type.replace("_", " ").toUpperCase()}
                      </Badge>
                      {txn.reference && (
                        <span className="text-xs text-muted-foreground font-mono">
                          {txn.reference}
                        </span>
                      )}
                    </div>
                    {txn.description && (
                      <p className="text-sm text-muted-foreground mb-1">{txn.description}</p>
                    )}
                    <p className="text-xs text-muted-foreground">
                      {txn.createdAt ? new Date(txn.createdAt).toLocaleString() : "N/A"}
                    </p>
                  </div>
                  <div className="text-right">
                    <p
                      className={`text-lg font-bold ${
                        ["topup", "refund", "commission", "referral_bonus"].includes(txn.type)
                          ? "text-neon-green"
                          : "text-destructive"
                      }`}
                      data-testid={`transaction-amount-${txn.id}`}
                    >
                      {["topup", "refund", "commission", "referral_bonus"].includes(txn.type) ? "+" : "-"}
                      GH₵ {txn.amount}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Balance: GH₵ {txn.balanceAfter}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </GlassCard>

        {/* Summary */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <GlassCard glowColor="gold" className="p-6">
            <p className="text-sm text-muted-foreground mb-2">Total Transactions</p>
            <p className="text-3xl font-bold">{transactions.length}</p>
          </GlassCard>
          <GlassCard glowColor="cyan" className="p-6">
            <p className="text-sm text-muted-foreground mb-2">Total Spent</p>
            <p className="text-3xl font-bold text-destructive">
              GH₵ {transactions
                .filter(t => ["purchase", "withdrawal"].includes(t.type))
                .reduce((sum, t) => sum + parseFloat(t.amount), 0)
                .toFixed(2)}
            </p>
          </GlassCard>
          <GlassCard glowColor="magenta" className="p-6">
            <p className="text-sm text-muted-foreground mb-2">Total Earned</p>
            <p className="text-3xl font-bold text-neon-green">
              GH₵ {transactions
                .filter(t => ["topup", "refund", "commission", "referral_bonus"].includes(t.type))
                .reduce((sum, t) => sum + parseFloat(t.amount), 0)
                .toFixed(2)}
            </p>
          </GlassCard>
        </div>
      </div>
    </div>
  );
}
