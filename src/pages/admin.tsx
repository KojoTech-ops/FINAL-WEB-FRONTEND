import { useState, useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useQuery, useMutation } from "@tanstack/react-query";
import { GlassCard } from "@/components/glass-card";
import { StatCard } from "@/components/stat-card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Users, Package, Activity, Settings as SettingsIcon, Plus } from "lucide-react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { User, Bundle, ApiLog } from "@shared/schema";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { isUnauthorizedError } from "@/lib/authUtils";

export default function Admin() {
  const { toast } = useToast();
  const { user, isAuthenticated, isLoading } = useAuth();
  const [isAddBundleOpen, setIsAddBundleOpen] = useState(false);
  const [newBundle, setNewBundle] = useState({
    provider: "mtn",
    name: "",
    dataSize: "",
    price: "",
    wholesalePrice: "",
    eta: "Instant",
    description: "",
  });

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

  const { data: users = [] } = useQuery<User[]>({
    queryKey: ["/api/admin/users"],
    enabled: isAuthenticated,
  });

  const { data: bundles = [] } = useQuery<Bundle[]>({
    queryKey: ["/api/admin/bundles"],
    enabled: isAuthenticated,
  });

  const { data: logs = [] } = useQuery<ApiLog[]>({
    queryKey: ["/api/admin/logs"],
    enabled: isAuthenticated,
  });

  const { data: systemConfig } = useQuery<{ primaryApiEnabled: boolean; backupApiEnabled: boolean; slowDeliveryTest: boolean }>({
    queryKey: ["/api/admin/config"],
    enabled: isAuthenticated,
  });

  const toggleApiMutation = useMutation({
    mutationFn: async (data: { key: string; value: boolean }) => {
      return await apiRequest("PATCH", "/api/admin/config", data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/config"] });
      toast({
        title: "Settings Updated",
        description: "API routing configuration has been updated",
      });
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
        title: "Update Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const addBundleMutation = useMutation({
    mutationFn: async (data: typeof newBundle) => {
      return await apiRequest("POST", "/api/admin/bundles", data);
    },
    onSuccess: () => {
      toast({
        title: "Bundle Added",
        description: "New bundle has been created successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/bundles"] });
      setIsAddBundleOpen(false);
      setNewBundle({
        provider: "mtn",
        name: "",
        dataSize: "",
        price: "",
        wholesalePrice: "",
        eta: "Instant",
        description: "",
      });
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
        title: "Failed to Add Bundle",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const updateUserRoleMutation = useMutation({
    mutationFn: async (data: { userId: string; role: string }) => {
      return await apiRequest("PATCH", "/api/admin/users", data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      toast({
        title: "User Updated",
        description: "User role has been changed",
      });
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
        title: "Update Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading admin panel...</div>
      </div>
    );
  }

  // For demo purposes, allow all users to access admin
  // In production, check if user has admin role

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-7xl mx-auto p-4 sm:p-6 lg:p-8 space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold mb-2">Admin Panel</h1>
          <p className="text-muted-foreground">Manage users, bundles, and system configuration</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <StatCard
            title="Total Users"
            value={users.length}
            icon={Users}
            glowColor="cyan"
          />
          <StatCard
            title="Active Bundles"
            value={bundles.filter(b => b.isActive).length}
            icon={Package}
            glowColor="gold"
          />
          <StatCard
            title="API Logs (24h)"
            value={logs.length}
            icon={Activity}
            glowColor="magenta"
          />
          <StatCard
            title="System Status"
            value="Online"
            icon={SettingsIcon}
            glowColor="cyan"
          />
        </div>

        <Tabs defaultValue="users" className="w-full">
          <TabsList className="grid grid-cols-4 w-full bg-background/50">
            <TabsTrigger value="users" data-testid="tab-users">Users</TabsTrigger>
            <TabsTrigger value="bundles" data-testid="tab-bundles">Bundles</TabsTrigger>
            <TabsTrigger value="config" data-testid="tab-config">API Config</TabsTrigger>
            <TabsTrigger value="logs" data-testid="tab-logs">Logs</TabsTrigger>
          </TabsList>

          <TabsContent value="users" className="mt-6">
            <GlassCard glowColor="cyan" className="p-6">
              <h2 className="text-xl font-bold mb-6">User Management</h2>
              <div className="space-y-3">
                {users.map((u) => (
                  <div
                    key={u.id}
                    className="flex items-center justify-between p-4 rounded-lg border border-border/50 hover-elevate"
                    data-testid={`user-${u.id}`}
                  >
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 rounded-full bg-gradient-to-br from-neon-cyan to-neon-magenta" />
                      <div>
                        <p className="font-semibold" data-testid={`user-name-${u.id}`}>
                          {u.firstName || ""} {u.lastName || ""}
                        </p>
                        <p className="text-sm text-muted-foreground">{u.email}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <Badge className={u.role === "agent" ? "bg-gold/20 text-gold" : ""} data-testid={`user-role-${u.id}`}>
                        {u.role}
                      </Badge>
                      <Select
                        value={u.role}
                        onValueChange={(value) => updateUserRoleMutation.mutate({ userId: u.id, role: value })}
                      >
                        <SelectTrigger className="w-32" data-testid={`select-role-${u.id}`}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="customer">Customer</SelectItem>
                          <SelectItem value="agent">Agent</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                ))}
              </div>
            </GlassCard>
          </TabsContent>

          <TabsContent value="bundles" className="mt-6">
            <GlassCard glowColor="cyan" className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold">Bundle Management</h2>
                <Button
                  onClick={() => setIsAddBundleOpen(true)}
                  className="bg-gold hover:bg-gold/90 text-gold-foreground"
                  data-testid="button-add-bundle"
                >
                  <Plus className="w-4 h-4 mr-2" />
                  Add Bundle
                </Button>
              </div>
              <div className="space-y-3">
                {bundles.map((bundle) => (
                  <div
                    key={bundle.id}
                    className="flex items-center justify-between p-4 rounded-lg border border-border/50 hover-elevate"
                    data-testid={`bundle-${bundle.id}`}
                  >
                    <div>
                      <p className="font-semibold" data-testid={`bundle-name-${bundle.id}`}>
                        {bundle.provider.toUpperCase()} - {bundle.dataSize}
                      </p>
                      <p className="text-sm text-muted-foreground">{bundle.name}</p>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <p className="font-bold">GH₵ {bundle.price}</p>
                        <p className="text-xs text-muted-foreground">
                          Wholesale: GH₵ {bundle.wholesalePrice}
                        </p>
                      </div>
                      <Badge className={bundle.isActive ? "bg-neon-green/20 text-neon-green" : "bg-muted"}>
                        {bundle.isActive ? "Active" : "Inactive"}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </GlassCard>
          </TabsContent>

          <TabsContent value="config" className="mt-6">
            <GlassCard glowColor="cyan" className="p-6">
              <h2 className="text-xl font-bold mb-6">API Routing Configuration</h2>
              <div className="space-y-6">
                <div className="flex items-center justify-between p-4 rounded-lg border border-border/50">
                  <div>
                    <Label className="text-base font-semibold">Primary API Provider</Label>
                    <p className="text-sm text-muted-foreground mt-1">
                      BulkDataGhana - Main provider for order processing
                    </p>
                  </div>
                  <Switch
                    checked={systemConfig?.primaryApiEnabled ?? true}
                    onCheckedChange={(checked) =>
                      toggleApiMutation.mutate({ key: "primaryApiEnabled", value: checked })
                    }
                    data-testid="switch-primary-api"
                  />
                </div>

                <div className="flex items-center justify-between p-4 rounded-lg border border-border/50">
                  <div>
                    <Label className="text-base font-semibold">Backup API Provider</Label>
                    <p className="text-sm text-muted-foreground mt-1">
                      Kojotech - Automatic failover on primary failure
                    </p>
                  </div>
                  <Switch
                    checked={systemConfig?.backupApiEnabled ?? true}
                    onCheckedChange={(checked) =>
                      toggleApiMutation.mutate({ key: "backupApiEnabled", value: checked })
                    }
                    data-testid="switch-backup-api"
                  />
                </div>

                <div className="flex items-center justify-between p-4 rounded-lg border border-gold/30 bg-gold/5">
                  <div>
                    <Label className="text-base font-semibold text-gold">Slow Delivery Test Mode</Label>
                    <p className="text-sm text-muted-foreground mt-1">
                      Simulate slow API responses for testing (5s delay)
                    </p>
                  </div>
                  <Switch
                    checked={systemConfig?.slowDeliveryTest ?? false}
                    onCheckedChange={(checked) =>
                      toggleApiMutation.mutate({ key: "slowDeliveryTest", value: checked })
                    }
                    data-testid="switch-slow-delivery"
                  />
                </div>
              </div>
            </GlassCard>
          </TabsContent>

          <TabsContent value="logs" className="mt-6">
            <GlassCard glowColor="cyan" className="p-6">
              <h2 className="text-xl font-bold mb-6">System Logs</h2>
              <div className="font-mono text-sm bg-background/50 p-4 rounded-lg max-h-96 overflow-y-auto space-y-2">
                {logs.length === 0 ? (
                  <p className="text-muted-foreground">No logs available</p>
                ) : (
                  logs.slice(0, 50).map((log) => (
                    <div key={log.id} className="text-xs" data-testid={`log-${log.id}`}>
                      <span className="text-muted-foreground">{log.createdAt ? new Date(log.createdAt).toISOString() : "N/A"}</span>
                      <span className={`ml-2 ${(log.statusCode ?? 0) >= 400 ? "text-destructive" : "text-neon-green"}`}>
                        [{log.statusCode ?? "N/A"}]
                      </span>
                      <span className="ml-2">{log.method} {log.endpoint}</span>
                      {log.duration && <span className="ml-2 text-muted-foreground">({log.duration}ms)</span>}
                    </div>
                  ))
                )}
              </div>
            </GlassCard>
          </TabsContent>
        </Tabs>
      </div>

      {/* Add Bundle Dialog */}
      <Dialog open={isAddBundleOpen} onOpenChange={setIsAddBundleOpen}>
        <DialogContent className="bg-card border-primary/20">
          <DialogHeader>
            <DialogTitle>Add New Bundle</DialogTitle>
          </DialogHeader>
          
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Provider</Label>
              <Select
                value={newBundle.provider}
                onValueChange={(value) => setNewBundle({ ...newBundle, provider: value })}
              >
                <SelectTrigger data-testid="select-bundle-provider">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="mtn">MTN</SelectItem>
                  <SelectItem value="vodafone">Vodafone</SelectItem>
                  <SelectItem value="airteltigo">AirtelTigo</SelectItem>
                  <SelectItem value="international">International</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Bundle Name</Label>
                <Input
                  value={newBundle.name}
                  onChange={(e) => setNewBundle({ ...newBundle, name: e.target.value })}
                  placeholder="Daily Bundle"
                  data-testid="input-bundle-name"
                />
              </div>
              <div className="space-y-2">
                <Label>Data Size</Label>
                <Input
                  value={newBundle.dataSize}
                  onChange={(e) => setNewBundle({ ...newBundle, dataSize: e.target.value })}
                  placeholder="1GB"
                  data-testid="input-bundle-size"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Retail Price (GH₵)</Label>
                <Input
                  type="number"
                  value={newBundle.price}
                  onChange={(e) => setNewBundle({ ...newBundle, price: e.target.value })}
                  placeholder="10.00"
                  data-testid="input-bundle-price"
                />
              </div>
              <div className="space-y-2">
                <Label>Wholesale Price (GH₵)</Label>
                <Input
                  type="number"
                  value={newBundle.wholesalePrice}
                  onChange={(e) => setNewBundle({ ...newBundle, wholesalePrice: e.target.value })}
                  placeholder="8.50"
                  data-testid="input-bundle-wholesale"
                />
              </div>
            </div>

            <div className="flex gap-3">
              <Button
                variant="outline"
                onClick={() => setIsAddBundleOpen(false)}
                className="flex-1"
                data-testid="button-cancel-add-bundle"
              >
                Cancel
              </Button>
              <Button
                onClick={() => addBundleMutation.mutate(newBundle)}
                disabled={addBundleMutation.isPending || !newBundle.name || !newBundle.price}
                className="flex-1 bg-gold hover:bg-gold/90 text-gold-foreground"
                data-testid="button-confirm-add-bundle"
              >
                {addBundleMutation.isPending ? "Adding..." : "Add Bundle"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
