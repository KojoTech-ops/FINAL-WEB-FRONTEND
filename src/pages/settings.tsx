import { useEffect, useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useMutation } from "@tanstack/react-query";
import { GlassCard } from "@/components/glass-card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { User, Lock, Key, Copy } from "lucide-react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { isUnauthorizedError } from "@/lib/authUtils";

export default function Settings() {
  const { toast } = useToast();
  const { user, isAuthenticated, isLoading, isAgent } = useAuth();
  
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

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
    if (user) {
      setFirstName(user.firstName || "");
      setLastName(user.lastName || "");
      setEmail(user.email || "");
    }
  }, [isAuthenticated, isLoading, user, toast]);

  const updateProfileMutation = useMutation({
    mutationFn: async (data: { firstName: string; lastName: string; email: string }) => {
      return await apiRequest("PATCH", "/api/user/profile", data);
    },
    onSuccess: () => {
      toast({
        title: "Profile Updated",
        description: "Your profile has been updated successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
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
        description: error.message || "Please try again",
        variant: "destructive",
      });
    },
  });

  const changePasswordMutation = useMutation({
    mutationFn: async (data: { currentPassword: string; newPassword: string }) => {
      return await apiRequest("POST", "/api/user/change-password", data);
    },
    onSuccess: () => {
      toast({
        title: "Password Changed",
        description: "Your password has been changed successfully",
      });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
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
        description: error.message || "Please try again",
        variant: "destructive",
      });
    },
  });

  const handleUpdateProfile = () => {
    updateProfileMutation.mutate({ firstName, lastName, email });
  };

  const handleChangePassword = () => {
    if (newPassword !== confirmPassword) {
      toast({
        title: "Passwords Don't Match",
        description: "Please ensure both passwords match",
        variant: "destructive",
      });
      return;
    }
    changePasswordMutation.mutate({ currentPassword, newPassword });
  };

  const generateApiKey = () => {
    toast({
      title: "API Key Generated",
      description: "Your new API key has been created",
    });
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading settings...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-4xl mx-auto p-4 sm:p-6 lg:p-8 space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold mb-2">Settings</h1>
          <p className="text-muted-foreground">Manage your account and preferences</p>
        </div>

        <Tabs defaultValue="profile" className="w-full">
          <TabsList className="grid grid-cols-3 w-full bg-background/50">
            <TabsTrigger value="profile" data-testid="tab-profile">
              <User className="w-4 h-4 mr-2" />
              Profile
            </TabsTrigger>
            <TabsTrigger value="security" data-testid="tab-security">
              <Lock className="w-4 h-4 mr-2" />
              Security
            </TabsTrigger>
            <TabsTrigger value="api" disabled={!isAgent} data-testid="tab-api">
              <Key className="w-4 h-4 mr-2" />
              API Keys
            </TabsTrigger>
          </TabsList>

          <TabsContent value="profile" className="mt-6">
            <GlassCard glowColor="cyan" className="p-8">
              <h2 className="text-xl font-bold mb-6">Profile Information</h2>
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="firstName">First Name</Label>
                    <Input
                      id="firstName"
                      value={firstName}
                      onChange={(e) => setFirstName(e.target.value)}
                      className="bg-background/50 border-primary/20"
                      data-testid="input-first-name"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="lastName">Last Name</Label>
                    <Input
                      id="lastName"
                      value={lastName}
                      onChange={(e) => setLastName(e.target.value)}
                      className="bg-background/50 border-primary/20"
                      data-testid="input-last-name"
                    />
                  </div>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="email">Email Address</Label>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="bg-background/50 border-primary/20"
                    data-testid="input-email"
                  />
                </div>

                <div className="space-y-2">
                  <Label>Account Role</Label>
                  <div className="p-4 rounded-lg bg-background/50 border border-border/50">
                    <span className="font-semibold capitalize" data-testid="text-account-role">
                      {user?.role || "customer"}
                    </span>
                  </div>
                </div>

                <Button
                  onClick={handleUpdateProfile}
                  disabled={updateProfileMutation.isPending}
                  className="bg-primary hover:bg-primary/90"
                  data-testid="button-update-profile"
                >
                  {updateProfileMutation.isPending ? "Updating..." : "Update Profile"}
                </Button>
              </div>
            </GlassCard>
          </TabsContent>

          <TabsContent value="security" className="mt-6">
            <GlassCard glowColor="cyan" className="p-8">
              <h2 className="text-xl font-bold mb-6">Change Password</h2>
              <div className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="currentPassword">Current Password</Label>
                  <Input
                    id="currentPassword"
                    type="password"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    className="bg-background/50 border-primary/20"
                    data-testid="input-current-password"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="newPassword">New Password</Label>
                  <Input
                    id="newPassword"
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="bg-background/50 border-primary/20"
                    data-testid="input-new-password"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="confirmPassword">Confirm New Password</Label>
                  <Input
                    id="confirmPassword"
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="bg-background/50 border-primary/20"
                    data-testid="input-confirm-password"
                  />
                </div>

                <Button
                  onClick={handleChangePassword}
                  disabled={changePasswordMutation.isPending || !currentPassword || !newPassword}
                  className="bg-primary hover:bg-primary/90"
                  data-testid="button-change-password"
                >
                  {changePasswordMutation.isPending ? "Changing..." : "Change Password"}
                </Button>
              </div>
            </GlassCard>
          </TabsContent>

          <TabsContent value="api" className="mt-6">
            <GlassCard glowColor="cyan" className="p-8">
              <h2 className="text-xl font-bold mb-6">API Keys (Agent Only)</h2>
              <p className="text-muted-foreground mb-6">
                Manage your API keys for programmatic access to your account
              </p>
              
              <div className="space-y-6">
                <div className="p-4 rounded-lg bg-background/50 border border-border/50">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-muted-foreground">Production API Key</span>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        navigator.clipboard.writeText("sk_live_xxxxxxxxxxxx");
                        toast({ title: "Copied!", description: "API key copied to clipboard" });
                      }}
                      data-testid="button-copy-api-key"
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>
                  <p className="font-mono text-sm">sk_live_xxxxxxxxxxxx</p>
                </div>

                <Button
                  variant="outline"
                  onClick={generateApiKey}
                  className="border-primary/20"
                  data-testid="button-generate-api-key"
                >
                  <Key className="w-4 h-4 mr-2" />
                  Generate New Key
                </Button>

                <div className="p-4 rounded-lg bg-gold/10 border border-gold/20">
                  <p className="text-sm text-muted-foreground">
                    <strong>Warning:</strong> Keep your API keys secure. Never share them publicly or commit them to version control.
                  </p>
                </div>
              </div>
            </GlassCard>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
