import { Button } from "@/components/ui/button";
import { GradientText } from "@/components/gradient-text";
import { GlassCard } from "@/components/glass-card";
import { Zap, Shield, Globe, TrendingUp, Users, Clock } from "lucide-react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";

export default function Landing() {
  const { toast } = useToast();

  const handleContact = (e: React.FormEvent) => {
    e.preventDefault();
    toast({
      title: "Message Sent",
      description: "We'll get back to you shortly!",
    });
  };

  return (
    <div className="min-h-screen">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 backdrop-blur-xl bg-background/40 border-b border-border/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-neon-cyan to-neon-magenta" />
              <span className="text-xl font-bold">
                <GradientText>DataHub</GradientText>
              </span>
            </div>
            <div className="hidden md:flex items-center gap-8">
              <a href="#features" className="text-sm hover:text-primary transition-colors">Features</a>
              <a href="#pricing" className="text-sm hover:text-primary transition-colors">Bundles</a>
              <a href="#faq" className="text-sm hover:text-primary transition-colors">FAQ</a>
              <a href="#contact" className="text-sm hover:text-primary transition-colors">Contact</a>
            </div>
            <Button 
              onClick={() => window.location.href = '/api/login'} 
              className="bg-gold hover:bg-gold/90 text-gold-foreground font-semibold shadow-lg shadow-gold/20"
              data-testid="button-login"
            >
              Get Started
            </Button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 px-4 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-neon-cyan/10 via-background to-neon-magenta/10 animate-gradient-shift" />
        <div className="relative max-w-7xl mx-auto text-center">
          <h1 className="text-5xl md:text-7xl font-bold mb-6 leading-tight">
            Premium Data Bundles
            <br />
            <GradientText className="text-5xl md:text-7xl font-bold">
              Delivered Instantly
            </GradientText>
          </h1>
          <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
            World-class data-selling platform with instant delivery, wholesale pricing for agents, 
            and seamless mobile money integration across all major providers.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Button 
              size="lg" 
              onClick={() => window.location.href = '/api/login'}
              className="bg-gold hover:bg-gold/90 text-gold-foreground font-semibold text-lg px-8 shadow-xl shadow-gold/30 hover:scale-105 transition-transform"
              data-testid="button-hero-cta"
            >
              Start Buying Now
            </Button>
            <Button 
              size="lg" 
              variant="outline" 
              className="border-primary text-primary hover:bg-primary/10 text-lg px-8 backdrop-blur-sm"
              data-testid="button-hero-secondary"
            >
              Become an Agent
            </Button>
          </div>
          
          {/* Floating Stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl mx-auto mt-16">
            <GlassCard glowColor="cyan" className="p-6">
              <div className="text-4xl font-bold text-neon-cyan mb-2">99.9%</div>
              <div className="text-sm text-muted-foreground">Success Rate</div>
            </GlassCard>
            <GlassCard glowColor="magenta" className="p-6">
              <div className="text-4xl font-bold text-neon-magenta mb-2">&lt;30s</div>
              <div className="text-sm text-muted-foreground">Avg. Delivery</div>
            </GlassCard>
            <GlassCard glowColor="gold" className="p-6">
              <div className="text-4xl font-bold text-gold mb-2">24/7</div>
              <div className="text-sm text-muted-foreground">Support</div>
            </GlassCard>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">
              Why Choose <GradientText>DataHub</GradientText>
            </h2>
            <p className="text-muted-foreground text-lg max-w-2xl mx-auto">
              Advanced features designed for modern data reselling and instant delivery
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {[
              { icon: Zap, title: "Instant Delivery", desc: "Orders processed in seconds with automatic failover routing" },
              { icon: Shield, title: "Secure Transactions", desc: "Bank-level security with encrypted payment processing" },
              { icon: Globe, title: "Multi-Provider", desc: "MTN, Vodafone, AirtelTigo, and International bundles" },
              { icon: TrendingUp, title: "Agent Dashboard", desc: "Real-time analytics, commissions, and wholesale pricing" },
              { icon: Users, title: "Referral Program", desc: "Earn credits for every successful referral and purchase" },
              { icon: Clock, title: "24/7 Availability", desc: "Round-the-clock service with automated order processing" },
            ].map((feature, i) => (
              <GlassCard key={i} glowColor="cyan" className="p-8 hover:scale-105 transition-transform">
                <feature.icon className="w-12 h-12 text-primary mb-4" />
                <h3 className="text-xl font-bold mb-3">{feature.title}</h3>
                <p className="text-muted-foreground">{feature.desc}</p>
              </GlassCard>
            ))}
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section id="faq" className="py-20 px-4 bg-card/20">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">
              Frequently Asked <GradientText>Questions</GradientText>
            </h2>
          </div>
          
          <Accordion type="single" collapsible className="space-y-4">
            {[
              {
                q: "How fast are orders delivered?",
                a: "Most orders are delivered instantly (within 30 seconds). We use advanced routing with automatic failover to ensure maximum reliability."
              },
              {
                q: "What payment methods do you accept?",
                a: "We accept MTN Mobile Money, Vodafone Cash, AirtelTigo Money, and wallet balance for seamless payments."
              },
              {
                q: "How do I become an agent?",
                a: "Simply register an account and contact support to upgrade to an agent account. Agents get wholesale pricing and commission tracking."
              },
              {
                q: "Is there a referral program?",
                a: "Yes! You'll get a unique referral code that earns you credits when friends sign up and make their first purchase."
              },
              {
                q: "What providers do you support?",
                a: "We support MTN, Vodafone, AirtelTigo for local bundles, plus International data bundles for global usage."
              },
            ].map((faq, i) => (
              <GlassCard key={i} glowColor="none">
                <AccordionItem value={`item-${i}`} className="border-none">
                  <AccordionTrigger className="px-6 hover:no-underline">
                    <span className="text-left font-semibold">{faq.q}</span>
                  </AccordionTrigger>
                  <AccordionContent className="px-6 pb-6 text-muted-foreground">
                    {faq.a}
                  </AccordionContent>
                </AccordionItem>
              </GlassCard>
            ))}
          </Accordion>
        </div>
      </section>

      {/* Contact Section */}
      <section id="contact" className="py-20 px-4">
        <div className="max-w-2xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-4xl font-bold mb-4">
              Get in <GradientText>Touch</GradientText>
            </h2>
            <p className="text-muted-foreground text-lg">
              Have questions? We're here to help
            </p>
          </div>
          
          <GlassCard glowColor="cyan" className="p-8">
            <form onSubmit={handleContact} className="space-y-6">
              <div>
                <Input 
                  placeholder="Your Name" 
                  className="bg-background/50 border-primary/20 focus:border-primary"
                  data-testid="input-contact-name"
                  required
                />
              </div>
              <div>
                <Input 
                  type="email" 
                  placeholder="Your Email" 
                  className="bg-background/50 border-primary/20 focus:border-primary"
                  data-testid="input-contact-email"
                  required
                />
              </div>
              <div>
                <Textarea 
                  placeholder="Your Message" 
                  rows={5}
                  className="bg-background/50 border-primary/20 focus:border-primary"
                  data-testid="input-contact-message"
                  required
                />
              </div>
              <Button 
                type="submit" 
                className="w-full bg-gold hover:bg-gold/90 text-gold-foreground font-semibold"
                data-testid="button-send-message"
              >
                Send Message
              </Button>
            </form>
          </GlassCard>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border/50 py-12 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
            <div>
              <div className="flex items-center gap-2 mb-4">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-neon-cyan to-neon-magenta" />
                <span className="text-lg font-bold">
                  <GradientText>DataHub</GradientText>
                </span>
              </div>
              <p className="text-sm text-muted-foreground">
                Premium data bundles delivered instantly
              </p>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Product</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><a href="#features" className="hover:text-primary transition-colors">Features</a></li>
                <li><a href="#pricing" className="hover:text-primary transition-colors">Pricing</a></li>
                <li><a href="#faq" className="hover:text-primary transition-colors">FAQ</a></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Company</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><a href="#about" className="hover:text-primary transition-colors">About</a></li>
                <li><a href="#contact" className="hover:text-primary transition-colors">Contact</a></li>
                <li><a href="#" className="hover:text-primary transition-colors">Privacy</a></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Newsletter</h4>
              <p className="text-sm text-muted-foreground mb-4">Get the latest updates</p>
              <div className="flex gap-2">
                <Input 
                  type="email" 
                  placeholder="Email" 
                  className="bg-background/50 text-sm"
                  data-testid="input-newsletter"
                />
                <Button size="sm" className="bg-primary" data-testid="button-subscribe">
                  Subscribe
                </Button>
              </div>
            </div>
          </div>
          <div className="border-t border-border/50 pt-8 text-center text-sm text-muted-foreground">
            © 2025 DataHub. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}
