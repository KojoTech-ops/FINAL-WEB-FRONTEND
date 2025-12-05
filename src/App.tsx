import { Switch, Route, Link } from "wouter";
import { useState } from "react";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useAuth } from "@/hooks/useAuth";
import NotFound from "@/pages/not-found";
import Landing from "@/pages/landing";
import CustomerDashboard from "@/pages/customer-dashboard";
import AgentDashboard from "@/pages/agent-dashboard";
import Marketplace from "@/pages/marketplace";
import Wallet from "@/pages/wallet";
import Referrals from "@/pages/referrals";
import Transactions from "@/pages/transactions";
import Settings from "@/pages/settings";
import Admin from "@/pages/admin";
import OrderDetails from "@/pages/order-details";
import Orders from "@/pages/orders";
import { Button } from "@/components/ui/button";
import { GradientText } from "@/components/gradient-text";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { 
  ShoppingBag, 
  Wallet as WalletIcon, 
  Users, 
  FileText, 
  Settings as SettingsIcon, 
  Shield, 
  LogOut,
  LayoutDashboard,
  TrendingUp,
  Menu,
  X
} from "lucide-react";

function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, isAgent } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const NavLinks = ({ onNavigate }: { onNavigate?: () => void }) => (
    <>
      <Link href="/dashboard" className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-white/5 text-sm font-medium transition-colors" onClick={onNavigate} data-testid="link-dashboard">
        <LayoutDashboard className="w-5 h-5" />
        Dashboard
      </Link>
      
      {isAgent && (
        <Link href="/agent" className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-white/5 text-sm font-medium transition-colors" onClick={onNavigate} data-testid="link-agent">
          <TrendingUp className="w-5 h-5" />
          Agent Panel
        </Link>
      )}

      <Link href="/marketplace" className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-white/5 text-sm font-medium transition-colors" onClick={onNavigate} data-testid="link-marketplace">
        <ShoppingBag className="w-5 h-5" />
        Marketplace
      </Link>

      <Link href="/wallet" className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-white/5 text-sm font-medium transition-colors" onClick={onNavigate} data-testid="link-wallet">
        <WalletIcon className="w-5 h-5" />
        Wallet
      </Link>

      <Link href="/referrals" className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-white/5 text-sm font-medium transition-colors" onClick={onNavigate} data-testid="link-referrals">
        <Users className="w-5 h-5" />
        Referrals
      </Link>

      <Link href="/transactions" className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-white/5 text-sm font-medium transition-colors" onClick={onNavigate} data-testid="link-transactions">
        <FileText className="w-5 h-5" />
        Transactions
      </Link>

      <Link href="/settings" className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-white/5 text-sm font-medium transition-colors" onClick={onNavigate} data-testid="link-settings">
        <SettingsIcon className="w-5 h-5" />
        Settings
      </Link>

      <Link href="/admin" className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-white/5 text-sm font-medium transition-colors" onClick={onNavigate} data-testid="link-admin">
        <Shield className="w-5 h-5" />
        Admin
      </Link>
    </>
  );

  return (
    <div className="min-h-screen flex flex-col lg:flex-row">
      {/* Mobile Header */}
      <header className="lg:hidden flex items-center justify-between p-4 bg-card border-b border-border/50">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-neon-cyan to-neon-magenta" />
          <span className="text-xl font-bold">
            <GradientText>DataHub</GradientText>
          </span>
        </div>
        <Sheet open={mobileMenuOpen} onOpenChange={setMobileMenuOpen}>
          <SheetTrigger asChild>
            <Button variant="ghost" size="icon">
              <Menu className="w-6 h-6" />
            </Button>
          </SheetTrigger>
          <SheetContent side="left" className="w-72 bg-card border-r border-border/50 p-0">
            <div className="p-6">
              <div className="flex items-center gap-2 mb-8">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-neon-cyan to-neon-magenta" />
                <span className="text-xl font-bold">
                  <GradientText>DataHub</GradientText>
                </span>
              </div>

              <nav className="space-y-2">
                <NavLinks onNavigate={() => setMobileMenuOpen(false)} />
              </nav>

              <div className="mt-8 pt-8 border-t border-border/50">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gradient-to-br from-neon-cyan to-neon-magenta" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold truncate">
                      {user?.firstName || ""} {user?.lastName || ""}
                    </p>
                    <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full justify-start border-destructive/20 text-destructive hover:bg-destructive/10"
                  onClick={() => window.location.href = '/api/logout'}
                >
                  <LogOut className="w-4 h-4 mr-2" />
                  Logout
                </Button>
              </div>
            </div>
          </SheetContent>
        </Sheet>
      </header>

      {/* Desktop Sidebar */}
      <aside className="w-64 bg-card border-r border-border/50 p-6 hidden lg:flex lg:flex-col">
        <div className="flex items-center gap-2 mb-8">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-neon-cyan to-neon-magenta" />
          <span className="text-xl font-bold">
            <GradientText>DataHub</GradientText>
          </span>
        </div>

        <nav className="space-y-2 flex-1">
          <NavLinks />
        </nav>

        <div className="pt-8 border-t border-border/50">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-full bg-gradient-to-br from-neon-cyan to-neon-magenta" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold truncate" data-testid="sidebar-user-name">
                {user?.firstName || ""} {user?.lastName || ""}
              </p>
              <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="w-full justify-start border-destructive/20 text-destructive hover:bg-destructive/10"
            onClick={() => window.location.href = '/api/logout'}
            data-testid="button-logout"
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </Button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  );
}

function Router() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading...</div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <Switch>
        <Route path="/" component={Landing} />
        <Route path="/:rest*" component={Landing} />
      </Switch>
    );
  }

  return (
    <Switch>
      <Route path="/">
        {() => (
          <DashboardLayout>
            <CustomerDashboard />
          </DashboardLayout>
        )}
      </Route>
      <Route path="/dashboard">
        {() => (
          <DashboardLayout>
            <CustomerDashboard />
          </DashboardLayout>
        )}
      </Route>
      <Route path="/agent">
        {() => (
          <DashboardLayout>
            <AgentDashboard />
          </DashboardLayout>
        )}
      </Route>
      <Route path="/marketplace">
        {() => (
          <DashboardLayout>
            <Marketplace />
          </DashboardLayout>
        )}
      </Route>
      <Route path="/wallet">
        {() => (
          <DashboardLayout>
            <Wallet />
          </DashboardLayout>
        )}
      </Route>
      <Route path="/referrals">
        {() => (
          <DashboardLayout>
            <Referrals />
          </DashboardLayout>
        )}
      </Route>
      <Route path="/transactions">
        {() => (
          <DashboardLayout>
            <Transactions />
          </DashboardLayout>
        )}
      </Route>
      <Route path="/settings">
        {() => (
          <DashboardLayout>
            <Settings />
          </DashboardLayout>
        )}
      </Route>
      <Route path="/admin">
        {() => (
          <DashboardLayout>
            <Admin />
          </DashboardLayout>
        )}
      </Route>
      <Route path="/orders">
        {() => (
          <DashboardLayout>
            <Orders />
          </DashboardLayout>
        )}
      </Route>
      <Route path="/orders/:id">
        {() => (
          <DashboardLayout>
            <OrderDetails />
          </DashboardLayout>
        )}
      </Route>
      <Route>
        {() => (
          <DashboardLayout>
            <NotFound />
          </DashboardLayout>
        )}
      </Route>
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
