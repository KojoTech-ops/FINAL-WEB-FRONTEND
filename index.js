var __defProp = Object.defineProperty;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  apiLogs: () => apiLogs,
  bundles: () => bundles,
  bundlesRelations: () => bundlesRelations,
  commissions: () => commissions,
  commissionsRelations: () => commissionsRelations,
  insertBundleSchema: () => insertBundleSchema,
  insertCommissionSchema: () => insertCommissionSchema,
  insertOrderSchema: () => insertOrderSchema,
  insertReferralSchema: () => insertReferralSchema,
  insertTransactionSchema: () => insertTransactionSchema,
  orderStatusEnum: () => orderStatusEnum,
  orders: () => orders,
  ordersRelations: () => ordersRelations,
  paymentMethodEnum: () => paymentMethodEnum,
  providerEnum: () => providerEnum,
  referrals: () => referrals,
  referralsRelations: () => referralsRelations,
  sessions: () => sessions,
  systemConfig: () => systemConfig,
  transactionTypeEnum: () => transactionTypeEnum,
  transactions: () => transactions,
  transactionsRelations: () => transactionsRelations,
  userRoleEnum: () => userRoleEnum,
  users: () => users,
  usersRelations: () => usersRelations,
  walletBalances: () => walletBalances,
  walletBalancesRelations: () => walletBalancesRelations
});
import { sql } from "drizzle-orm";
import {
  index,
  jsonb,
  pgTable,
  timestamp,
  varchar,
  text,
  decimal,
  integer,
  pgEnum,
  boolean
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { relations } from "drizzle-orm";
var sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull()
  },
  (table) => [index("IDX_session_expire").on(table.expire)]
);
var userRoleEnum = pgEnum("user_role", ["customer", "agent"]);
var orderStatusEnum = pgEnum("order_status", ["pending", "processing", "completed", "failed"]);
var transactionTypeEnum = pgEnum("transaction_type", ["purchase", "topup", "withdrawal", "refund", "commission", "referral_bonus"]);
var providerEnum = pgEnum("provider", ["mtn", "vodafone", "airteltigo", "international"]);
var paymentMethodEnum = pgEnum("payment_method", ["mtn_momo", "vodafone_cash", "airteltigo_money", "wallet"]);
var users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  role: userRoleEnum("role").notNull().default("customer"),
  referralCode: varchar("referral_code", { length: 12 }).unique(),
  referredBy: varchar("referred_by").references(() => users.id),
  commissionRate: decimal("commission_rate", { precision: 5, scale: 2 }).default("0"),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var usersRelations = relations(users, ({ one, many }) => ({
  referrer: one(users, {
    fields: [users.referredBy],
    references: [users.id]
  }),
  orders: many(orders),
  transactions: many(transactions),
  walletBalance: one(walletBalances),
  referrals: many(referrals),
  commissions: many(commissions)
}));
var bundles = pgTable("bundles", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  provider: providerEnum("provider").notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  dataSize: varchar("data_size", { length: 50 }).notNull(),
  price: decimal("price", { precision: 10, scale: 2 }).notNull(),
  wholesalePrice: decimal("wholesale_price", { precision: 10, scale: 2 }).notNull(),
  eta: varchar("eta", { length: 50 }).default("Instant"),
  isActive: boolean("is_active").default(true),
  description: text("description"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var bundlesRelations = relations(bundles, ({ many }) => ({
  orders: many(orders)
}));
var orders = pgTable("orders", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id),
  bundleId: varchar("bundle_id").notNull().references(() => bundles.id),
  recipientPhone: varchar("recipient_phone", { length: 20 }).notNull(),
  status: orderStatusEnum("status").notNull().default("pending"),
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  provider: providerEnum("provider").notNull(),
  apiProvider: varchar("api_provider", { length: 50 }),
  failoverAttempts: integer("failover_attempts").default(0),
  errorMessage: text("error_message"),
  processedAt: timestamp("processed_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var ordersRelations = relations(orders, ({ one }) => ({
  user: one(users, {
    fields: [orders.userId],
    references: [users.id]
  }),
  bundle: one(bundles, {
    fields: [orders.bundleId],
    references: [bundles.id]
  })
}));
var transactions = pgTable("transactions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id),
  type: transactionTypeEnum("type").notNull(),
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  balanceBefore: decimal("balance_before", { precision: 10, scale: 2 }).notNull(),
  balanceAfter: decimal("balance_after", { precision: 10, scale: 2 }).notNull(),
  reference: varchar("reference", { length: 255 }),
  orderId: varchar("order_id").references(() => orders.id),
  description: text("description"),
  metadata: jsonb("metadata"),
  createdAt: timestamp("created_at").defaultNow()
});
var transactionsRelations = relations(transactions, ({ one }) => ({
  user: one(users, {
    fields: [transactions.userId],
    references: [users.id]
  }),
  order: one(orders, {
    fields: [transactions.orderId],
    references: [orders.id]
  })
}));
var walletBalances = pgTable("wallet_balances", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().unique().references(() => users.id),
  balance: decimal("balance", { precision: 10, scale: 2 }).notNull().default("0"),
  updatedAt: timestamp("updated_at").defaultNow()
});
var walletBalancesRelations = relations(walletBalances, ({ one }) => ({
  user: one(users, {
    fields: [walletBalances.userId],
    references: [users.id]
  })
}));
var referrals = pgTable("referrals", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  referrerId: varchar("referrer_id").notNull().references(() => users.id),
  referredId: varchar("referred_id").notNull().references(() => users.id),
  bonusAmount: decimal("bonus_amount", { precision: 10, scale: 2 }).default("0"),
  firstPurchaseBonus: decimal("first_purchase_bonus", { precision: 10, scale: 2 }).default("0"),
  isPaid: boolean("is_paid").default(false),
  createdAt: timestamp("created_at").defaultNow()
});
var referralsRelations = relations(referrals, ({ one }) => ({
  referrer: one(users, {
    fields: [referrals.referrerId],
    references: [users.id],
    relationName: "referrer"
  }),
  referred: one(users, {
    fields: [referrals.referredId],
    references: [users.id],
    relationName: "referred"
  })
}));
var commissions = pgTable("commissions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  agentId: varchar("agent_id").notNull().references(() => users.id),
  orderId: varchar("order_id").notNull().references(() => orders.id),
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  rate: decimal("rate", { precision: 5, scale: 2 }).notNull(),
  isPaid: boolean("is_paid").default(false),
  paidAt: timestamp("paid_at"),
  createdAt: timestamp("created_at").defaultNow()
});
var commissionsRelations = relations(commissions, ({ one }) => ({
  agent: one(users, {
    fields: [commissions.agentId],
    references: [users.id]
  }),
  order: one(orders, {
    fields: [commissions.orderId],
    references: [orders.id]
  })
}));
var apiLogs = pgTable("api_logs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  endpoint: varchar("endpoint", { length: 255 }).notNull(),
  method: varchar("method", { length: 10 }).notNull(),
  statusCode: integer("status_code"),
  userId: varchar("user_id").references(() => users.id),
  requestBody: jsonb("request_body"),
  responseBody: jsonb("response_body"),
  errorMessage: text("error_message"),
  duration: integer("duration"),
  createdAt: timestamp("created_at").defaultNow()
});
var systemConfig = pgTable("system_config", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  key: varchar("key", { length: 255 }).notNull().unique(),
  value: jsonb("value").notNull(),
  description: text("description"),
  updatedAt: timestamp("updated_at").defaultNow()
});
var insertBundleSchema = createInsertSchema(bundles).omit({ id: true, createdAt: true, updatedAt: true });
var insertOrderSchema = createInsertSchema(orders).omit({ id: true, createdAt: true, updatedAt: true, processedAt: true });
var insertTransactionSchema = createInsertSchema(transactions).omit({ id: true, createdAt: true });
var insertReferralSchema = createInsertSchema(referrals).omit({ id: true, createdAt: true });
var insertCommissionSchema = createInsertSchema(commissions).omit({ id: true, createdAt: true, paidAt: true });

// server/db.ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
neonConfig.webSocketConstructor = ws;
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var pool = new Pool({ connectionString: process.env.DATABASE_URL });
var db = drizzle({ client: pool, schema: schema_exports });

// server/storage.ts
import { eq, desc, and } from "drizzle-orm";
var DatabaseStorage = class {
  // User operations
  async getUser(id) {
    const result = await db.select().from(users).where(eq(users.id, id));
    return result[0];
  }
  async upsertUser(userData) {
    const result = await db.insert(users).values({
      ...userData,
      referralCode: userData.id ? `REF${userData.id.substring(0, 8).toUpperCase()}` : void 0
    }).onConflictDoUpdate({
      target: users.id,
      set: {
        ...userData,
        updatedAt: /* @__PURE__ */ new Date()
      }
    }).returning();
    const user = result[0];
    await this.createWalletBalance(user.id).catch(() => {
    });
    return user;
  }
  async updateUserRole(userId, role) {
    await db.update(users).set({ role, updatedAt: /* @__PURE__ */ new Date() }).where(eq(users.id, userId));
  }
  // Bundle operations
  async getBundles(filters) {
    let query = db.select().from(bundles);
    const conditions = [];
    if (filters?.provider) {
      conditions.push(eq(bundles.provider, filters.provider));
    }
    if (filters?.isActive !== void 0) {
      conditions.push(eq(bundles.isActive, filters.isActive));
    }
    if (conditions.length > 0) {
      query = query.where(and(...conditions));
    }
    return await query;
  }
  async getBundle(id) {
    const [bundle] = await db.select().from(bundles).where(eq(bundles.id, id));
    return bundle;
  }
  async createBundle(bundle) {
    const [newBundle] = await db.insert(bundles).values(bundle).returning();
    return newBundle;
  }
  async updateBundle(id, bundle) {
    const [updated] = await db.update(bundles).set({ ...bundle, updatedAt: /* @__PURE__ */ new Date() }).where(eq(bundles.id, id)).returning();
    return updated;
  }
  // Order operations
  async createOrder(order) {
    const [newOrder] = await db.insert(orders).values(order).returning();
    return newOrder;
  }
  async getOrder(id) {
    const [order] = await db.select().from(orders).where(eq(orders.id, id));
    return order;
  }
  async getUserOrders(userId, limit = 50) {
    return await db.select().from(orders).where(eq(orders.userId, userId)).orderBy(desc(orders.createdAt)).limit(limit);
  }
  async updateOrderStatus(id, status, errorMessage) {
    await db.update(orders).set({
      status,
      errorMessage,
      processedAt: status === "completed" || status === "failed" ? /* @__PURE__ */ new Date() : void 0,
      updatedAt: /* @__PURE__ */ new Date()
    }).where(eq(orders.id, id));
  }
  // Transaction operations
  async createTransaction(transaction) {
    const [newTransaction] = await db.insert(transactions).values(transaction).returning();
    return newTransaction;
  }
  async getUserTransactions(userId) {
    return await db.select().from(transactions).where(eq(transactions.userId, userId)).orderBy(desc(transactions.createdAt));
  }
  // Wallet operations
  async getWalletBalance(userId) {
    const [balance] = await db.select().from(walletBalances).where(eq(walletBalances.userId, userId));
    return balance;
  }
  async updateWalletBalance(userId, newBalance) {
    await db.update(walletBalances).set({ balance: newBalance, updatedAt: /* @__PURE__ */ new Date() }).where(eq(walletBalances.userId, userId));
  }
  async createWalletBalance(userId) {
    const [balance] = await db.insert(walletBalances).values({ userId, balance: "0" }).onConflictDoNothing().returning();
    return balance || await this.getWalletBalance(userId);
  }
  // Referral operations
  async createReferral(referral) {
    const [newReferral] = await db.insert(referrals).values(referral).returning();
    return newReferral;
  }
  async getUserReferrals(userId) {
    return await db.select().from(referrals).where(eq(referrals.referrerId, userId)).orderBy(desc(referrals.createdAt));
  }
  // Commission operations
  async createCommission(commission) {
    const [newCommission] = await db.insert(commissions).values(commission).returning();
    return newCommission;
  }
  async getAgentCommissions(agentId) {
    return await db.select().from(commissions).where(eq(commissions.agentId, agentId)).orderBy(desc(commissions.createdAt));
  }
  // API logs
  async createApiLog(log2) {
    await db.insert(apiLogs).values(log2);
  }
  async getApiLogs(limit = 100) {
    return await db.select().from(apiLogs).orderBy(desc(apiLogs.createdAt)).limit(limit);
  }
  // System config
  async getSystemConfig(key) {
    const [config2] = await db.select().from(systemConfig).where(eq(systemConfig.key, key));
    return config2;
  }
  async updateSystemConfig(key, value) {
    await db.insert(systemConfig).values({ key, value, updatedAt: /* @__PURE__ */ new Date() }).onConflictDoUpdate({
      target: systemConfig.key,
      set: { value, updatedAt: /* @__PURE__ */ new Date() }
    });
  }
  // Stats
  async getAllUsers() {
    const result = await db.select().from(users);
    return result;
  }
};
var storage = new DatabaseStorage();

// server/replitAuth.ts
import * as client from "openid-client";
import { Strategy } from "openid-client/passport";
import passport from "passport";
import session from "express-session";
import memoize from "memoizee";
import connectPg from "connect-pg-simple";
var getOidcConfig = memoize(
  async () => {
    return await client.discovery(
      new URL(process.env.ISSUER_URL ?? "https://replit.com/oidc"),
      process.env.REPL_ID
    );
  },
  { maxAge: 3600 * 1e3 }
);
function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1e3;
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtl,
    tableName: "sessions"
  });
  return session({
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: sessionTtl
    }
  });
}
function updateUserSession(user, tokens) {
  user.claims = tokens.claims();
  user.access_token = tokens.access_token;
  user.refresh_token = tokens.refresh_token;
  user.expires_at = user.claims?.exp;
}
async function upsertUser(claims) {
  await storage.upsertUser({
    id: claims["sub"],
    email: claims["email"],
    firstName: claims["first_name"],
    lastName: claims["last_name"],
    profileImageUrl: claims["profile_image_url"]
  });
}
async function setupAuth(app2) {
  app2.set("trust proxy", 1);
  app2.use(getSession());
  app2.use(passport.initialize());
  app2.use(passport.session());
  const config2 = await getOidcConfig();
  const verify = async (tokens, verified) => {
    const user = {};
    updateUserSession(user, tokens);
    await upsertUser(tokens.claims());
    verified(null, user);
  };
  const registeredStrategies = /* @__PURE__ */ new Set();
  const ensureStrategy = (domain) => {
    const strategyName = `replitauth:${domain}`;
    if (!registeredStrategies.has(strategyName)) {
      const strategy = new Strategy(
        {
          name: strategyName,
          config: config2,
          scope: "openid email profile offline_access",
          callbackURL: `https://${domain}/api/callback`
        },
        verify
      );
      passport.use(strategy);
      registeredStrategies.add(strategyName);
    }
  };
  passport.serializeUser((user, cb) => cb(null, user));
  passport.deserializeUser((user, cb) => cb(null, user));
  app2.get("/api/login", (req, res, next) => {
    ensureStrategy(req.hostname);
    passport.authenticate(`replitauth:${req.hostname}`, {
      prompt: "login consent",
      scope: ["openid", "email", "profile", "offline_access"]
    })(req, res, next);
  });
  app2.get("/api/callback", (req, res, next) => {
    ensureStrategy(req.hostname);
    passport.authenticate(`replitauth:${req.hostname}`, {
      successReturnToOrRedirect: "/",
      failureRedirect: "/api/login"
    })(req, res, next);
  });
  app2.get("/api/logout", (req, res) => {
    req.logout(() => {
      res.redirect(
        client.buildEndSessionUrl(config2, {
          client_id: process.env.REPL_ID,
          post_logout_redirect_uri: `${req.protocol}://${req.hostname}`
        }).href
      );
    });
  });
}
var isAuthenticated = async (req, res, next) => {
  const user = req.user;
  if (!req.isAuthenticated() || !user.expires_at) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const now = Math.floor(Date.now() / 1e3);
  if (now <= user.expires_at) {
    return next();
  }
  const refreshToken = user.refresh_token;
  if (!refreshToken) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  try {
    const config2 = await getOidcConfig();
    const tokenResponse = await client.refreshTokenGrant(config2, refreshToken);
    updateUserSession(user, tokenResponse);
    return next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
};

// server/config.ts
var config = {
  // Paystack API Keys
  paystack: {
    publicKey: process.env.PAYSTACK_PUBLIC_KEY || "",
    secretKey: process.env.PAYSTACK_SECRET_KEY || "",
    baseUrl: "https://api.paystack.co"
  },
  // Ghana Mobile Money API Keys (Mock)
  mtn: {
    apiKey: process.env.MTN_MOMO_API_KEY || "mock_mtn_api_key",
    apiSecret: process.env.MTN_MOMO_API_SECRET || "mock_mtn_api_secret",
    subscriptionKey: process.env.MTN_SUBSCRIPTION_KEY || "mock_mtn_subscription_key"
  },
  vodafone: {
    apiKey: process.env.VODAFONE_CASH_API_KEY || "mock_vodafone_api_key",
    apiSecret: process.env.VODAFONE_CASH_API_SECRET || "mock_vodafone_api_secret"
  },
  airteltigo: {
    apiKey: process.env.AIRTELTIGO_API_KEY || "mock_airteltigo_api_key",
    apiSecret: process.env.AIRTELTIGO_API_SECRET || "mock_airteltigo_api_secret"
  },
  // Data Provider APIs (Mock)
  bulkDataGhana: {
    apiUrl: process.env.BULKDATA_GHANA_API_URL || "https://api.bulkdataghana.com",
    apiKey: process.env.BULKDATA_GHANA_API_KEY || "mock_bulkdata_api_key"
  },
  kojotech: {
    apiUrl: process.env.KOJOTECH_API_URL || "https://api.kojotech.com",
    apiKey: process.env.KOJOTECH_API_KEY || "mock_kojotech_api_key"
  },
  // System configuration
  primaryProviderEnabled: true,
  backupProviderEnabled: true,
  slowDeliveryTest: false,
  providerTimeout: 5e3,
  // 5 seconds
  // Referral bonuses
  referralSignupBonus: 5,
  referralFirstPurchaseBonus: 0.1
  // 10%
};

// server/routes.ts
var MockProviderService = class {
  slowDeliveryEnabled = false;
  setSlowDelivery(enabled) {
    this.slowDeliveryEnabled = enabled;
  }
  async processBundleOrder(bundleId, recipientPhone, provider) {
    if (this.slowDeliveryEnabled) {
      await new Promise((resolve) => setTimeout(resolve, 5e3));
    } else {
      await new Promise((resolve) => setTimeout(resolve, Math.random() * 1e3 + 500));
    }
    const isPrimary = Math.random() > 0.5;
    const successRate = isPrimary ? 0.95 : 0.9;
    const success = Math.random() < successRate;
    if (!success) {
      return {
        success: false,
        provider: isPrimary ? "BulkDataGhana" : "Kojotech",
        errorMessage: "Provider returned error: Insufficient balance or invalid recipient"
      };
    }
    return {
      success: true,
      provider: isPrimary ? "BulkDataGhana" : "Kojotech"
    };
  }
  async processWithFailover(bundleId, recipientPhone, provider) {
    let failoverAttempts = 0;
    if (config.primaryProviderEnabled) {
      const result = await this.processBundleOrder(bundleId, recipientPhone, provider);
      failoverAttempts++;
      if (result.success) {
        return { ...result, failoverAttempts };
      }
    }
    if (config.backupProviderEnabled) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      const result = await this.processBundleOrder(bundleId, recipientPhone, provider);
      failoverAttempts++;
      return { ...result, failoverAttempts };
    }
    return {
      success: false,
      provider: "None",
      errorMessage: "All providers failed",
      failoverAttempts
    };
  }
};
var mockProvider = new MockProviderService();
async function registerRoutes(app2) {
  await setupAuth(app2);
  app2.get("/api/auth/user", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      res.json(user);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });
  app2.get("/api/bundles", async (req, res) => {
    try {
      const bundles2 = await storage.getBundles({ isActive: true });
      res.json(bundles2);
    } catch (error) {
      console.error("Error fetching bundles:", error);
      res.status(500).json({ message: "Failed to fetch bundles" });
    }
  });
  app2.post("/api/orders", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const { bundleId, recipientPhone } = req.body;
      if (!bundleId || !recipientPhone) {
        return res.status(400).json({ message: "Missing required fields" });
      }
      const bundle = await storage.getBundle(bundleId);
      if (!bundle) {
        return res.status(404).json({ message: "Bundle not found" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      const wallet = await storage.getWalletBalance(userId);
      const currentBalance = parseFloat(wallet?.balance || "0");
      const price = user.role === "agent" ? parseFloat(bundle.wholesalePrice) : parseFloat(bundle.price);
      if (currentBalance < price) {
        return res.status(400).json({ message: "Insufficient wallet balance" });
      }
      const order = await storage.createOrder({
        userId,
        bundleId,
        recipientPhone,
        status: "pending",
        amount: price.toString(),
        provider: bundle.provider
      });
      (async () => {
        await storage.updateOrderStatus(order.id, "processing");
        const result = await mockProvider.processWithFailover(bundleId, recipientPhone, bundle.provider);
        if (result.success) {
          await storage.updateOrderStatus(order.id, "completed");
          const newBalance = (currentBalance - price).toFixed(2);
          await storage.updateWalletBalance(userId, newBalance);
          await storage.createTransaction({
            userId,
            type: "purchase",
            amount: price.toString(),
            balanceBefore: currentBalance.toString(),
            balanceAfter: newBalance,
            orderId: order.id,
            description: `Purchased ${bundle.dataSize} ${bundle.provider} data`
          });
          if (user.role === "agent" && user.commissionRate) {
            const commissionAmount = (price * parseFloat(user.commissionRate) / 100).toFixed(2);
            await storage.createCommission({
              agentId: userId,
              orderId: order.id,
              amount: commissionAmount,
              rate: user.commissionRate,
              isPaid: false
            });
          }
        } else {
          await storage.updateOrderStatus(order.id, "failed", result.errorMessage);
        }
      })();
      res.json(order);
    } catch (error) {
      console.error("Error creating order:", error);
      res.status(500).json({ message: "Failed to create order" });
    }
  });
  app2.get("/api/orders/recent", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const orders2 = await storage.getUserOrders(userId, 10);
      res.json(orders2);
    } catch (error) {
      console.error("Error fetching orders:", error);
      res.status(500).json({ message: "Failed to fetch orders" });
    }
  });
  app2.get("/api/orders", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const orders2 = await storage.getUserOrders(userId, 100);
      res.json(orders2);
    } catch (error) {
      console.error("Error fetching all orders:", error);
      res.status(500).json({ message: "Failed to fetch orders" });
    }
  });
  app2.get("/api/orders/:id", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const order = await storage.getOrder(id);
      if (!order) {
        return res.status(404).json({ message: "Order not found" });
      }
      if (order.userId !== userId) {
        return res.status(403).json({ message: "Access denied" });
      }
      res.json(order);
    } catch (error) {
      console.error("Error fetching order:", error);
      res.status(500).json({ message: "Failed to fetch order" });
    }
  });
  app2.get("/api/bundles/:id", isAuthenticated, async (req, res) => {
    try {
      const { id } = req.params;
      const bundle = await storage.getBundle(id);
      if (!bundle) {
        return res.status(404).json({ message: "Bundle not found" });
      }
      res.json(bundle);
    } catch (error) {
      console.error("Error fetching bundle:", error);
      res.status(500).json({ message: "Failed to fetch bundle" });
    }
  });
  app2.get("/api/wallet/balance", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const balance = await storage.getWalletBalance(userId);
      res.json(balance || { balance: "0.00" });
    } catch (error) {
      console.error("Error fetching wallet balance:", error);
      res.status(500).json({ message: "Failed to fetch wallet balance" });
    }
  });
  app2.post("/api/wallet/topup", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const { amount, provider, phoneNumber } = req.body;
      if (!amount || !provider || !phoneNumber) {
        return res.status(400).json({ message: "Missing required fields" });
      }
      const wallet = await storage.getWalletBalance(userId);
      const currentBalance = parseFloat(wallet?.balance || "0");
      const topUpAmount = parseFloat(amount);
      const newBalance = (currentBalance + topUpAmount).toFixed(2);
      await storage.updateWalletBalance(userId, newBalance);
      await storage.createTransaction({
        userId,
        type: "topup",
        amount,
        balanceBefore: currentBalance.toString(),
        balanceAfter: newBalance,
        description: `Top-up via ${provider}`,
        reference: `TOPUP-${Date.now()}`,
        metadata: { provider, phoneNumber }
      });
      res.json({ success: true, newBalance });
    } catch (error) {
      console.error("Error processing top-up:", error);
      res.status(500).json({ message: "Failed to process top-up" });
    }
  });
  app2.post("/api/paystack/initialize", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const { amount, email } = req.body;
      if (!amount || !email) {
        return res.status(400).json({ message: "Amount and email are required" });
      }
      const amountInKobo = Math.round(parseFloat(amount) * 100);
      const reference = `TOPUP-${userId}-${Date.now()}`;
      const response = await fetch(`${config.paystack.baseUrl}/transaction/initialize`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${config.paystack.secretKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          amount: amountInKobo,
          email,
          reference,
          callback_url: `${req.protocol}://${req.get("host")}/wallet?payment=success`,
          metadata: {
            userId,
            type: "wallet_topup"
          }
        })
      });
      const data = await response.json();
      if (!data.status) {
        return res.status(400).json({ message: data.message || "Failed to initialize payment" });
      }
      res.json({
        success: true,
        authorization_url: data.data.authorization_url,
        access_code: data.data.access_code,
        reference: data.data.reference
      });
    } catch (error) {
      console.error("Error initializing Paystack payment:", error);
      res.status(500).json({ message: "Failed to initialize payment" });
    }
  });
  app2.get("/api/paystack/verify/:reference", isAuthenticated, async (req, res) => {
    try {
      const { reference } = req.params;
      const userId = req.user.claims.sub;
      const response = await fetch(`${config.paystack.baseUrl}/transaction/verify/${reference}`, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${config.paystack.secretKey}`
        }
      });
      const data = await response.json();
      if (!data.status || data.data.status !== "success") {
        return res.status(400).json({
          success: false,
          message: data.message || "Payment verification failed"
        });
      }
      const amountPaid = data.data.amount / 100;
      const wallet = await storage.getWalletBalance(userId);
      const currentBalance = parseFloat(wallet?.balance || "0");
      const newBalance = (currentBalance + amountPaid).toFixed(2);
      await storage.updateWalletBalance(userId, newBalance);
      await storage.createTransaction({
        userId,
        type: "topup",
        amount: amountPaid.toString(),
        balanceBefore: currentBalance.toString(),
        balanceAfter: newBalance,
        description: `Top-up via Paystack`,
        reference,
        metadata: {
          provider: "paystack",
          paystack_reference: reference,
          channel: data.data.channel
        }
      });
      res.json({
        success: true,
        newBalance,
        amount: amountPaid,
        message: "Payment verified and wallet credited"
      });
    } catch (error) {
      console.error("Error verifying Paystack payment:", error);
      res.status(500).json({ message: "Failed to verify payment" });
    }
  });
  app2.post("/api/paystack/webhook", async (req, res) => {
    try {
      const hash = __require("crypto").createHmac("sha512", config.paystack.secretKey).update(JSON.stringify(req.body)).digest("hex");
      if (hash !== req.headers["x-paystack-signature"]) {
        return res.status(401).json({ message: "Invalid signature" });
      }
      const event = req.body;
      if (event.event === "charge.success") {
        const { reference, amount, metadata } = event.data;
        const userId = metadata?.userId;
        if (userId) {
          const amountPaid = amount / 100;
          const wallet = await storage.getWalletBalance(userId);
          const currentBalance = parseFloat(wallet?.balance || "0");
          const newBalance = (currentBalance + amountPaid).toFixed(2);
          await storage.updateWalletBalance(userId, newBalance);
          await storage.createTransaction({
            userId,
            type: "topup",
            amount: amountPaid.toString(),
            balanceBefore: currentBalance.toString(),
            balanceAfter: newBalance,
            description: `Top-up via Paystack (Webhook)`,
            reference,
            metadata: { provider: "paystack", webhook: true }
          });
        }
      }
      res.sendStatus(200);
    } catch (error) {
      console.error("Error processing Paystack webhook:", error);
      res.sendStatus(500);
    }
  });
  app2.get("/api/paystack/config", isAuthenticated, async (req, res) => {
    res.json({ publicKey: config.paystack.publicKey });
  });
  app2.get("/api/wallet/transactions", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const transactions2 = await storage.getUserTransactions(userId);
      res.json(transactions2);
    } catch (error) {
      console.error("Error fetching transactions:", error);
      res.status(500).json({ message: "Failed to fetch transactions" });
    }
  });
  app2.get("/api/transactions", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const transactions2 = await storage.getUserTransactions(userId);
      res.json(transactions2);
    } catch (error) {
      console.error("Error fetching transactions:", error);
      res.status(500).json({ message: "Failed to fetch transactions" });
    }
  });
  app2.get("/api/referrals/stats", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const referrals2 = await storage.getUserReferrals(userId);
      const totalReferrals = referrals2.length;
      const earnedCredits = referrals2.reduce(
        (sum, ref) => sum + parseFloat(ref.bonusAmount || "0") + parseFloat(ref.firstPurchaseBonus || "0"),
        0
      ).toFixed(2);
      const conversionRate = totalReferrals > 0 ? (referrals2.filter((r) => r.isPaid).length / totalReferrals * 100).toFixed(0) + "%" : "0%";
      res.json({ totalReferrals, earnedCredits, conversionRate });
    } catch (error) {
      console.error("Error fetching referral stats:", error);
      res.status(500).json({ message: "Failed to fetch referral stats" });
    }
  });
  app2.get("/api/referrals/list", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const referrals2 = await storage.getUserReferrals(userId);
      const list = await Promise.all(referrals2.map(async (ref) => {
        const referredUser = await storage.getUser(ref.referredId);
        return {
          id: ref.id,
          referredName: referredUser ? `${referredUser.firstName} ${referredUser.lastName}` : "Unknown",
          signupDate: ref.createdAt,
          status: ref.isPaid ? "completed" : "pending",
          earnedAmount: (parseFloat(ref.bonusAmount || "0") + parseFloat(ref.firstPurchaseBonus || "0")).toFixed(2)
        };
      }));
      res.json(list);
    } catch (error) {
      console.error("Error fetching referral list:", error);
      res.status(500).json({ message: "Failed to fetch referral list" });
    }
  });
  app2.get("/api/stats/customer", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const orders2 = await storage.getUserOrders(userId);
      const transactions2 = await storage.getUserTransactions(userId);
      const totalOrders = orders2.length;
      const totalSpent = transactions2.filter((t) => t.type === "purchase").reduce((sum, t) => sum + parseFloat(t.amount), 0).toFixed(2);
      const successRate = totalOrders > 0 ? (orders2.filter((o) => o.status === "completed").length / totalOrders * 100).toFixed(0) + "%" : "100%";
      res.json({ totalOrders, totalSpent, successRate });
    } catch (error) {
      console.error("Error fetching customer stats:", error);
      res.status(500).json({ message: "Failed to fetch stats" });
    }
  });
  app2.get("/api/stats/agent", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const commissions2 = await storage.getAgentCommissions(userId);
      const orders2 = await storage.getUserOrders(userId);
      const totalCommissions = commissions2.reduce((sum, c) => sum + parseFloat(c.amount), 0).toFixed(2);
      const pendingPayouts = commissions2.filter((c) => !c.isPaid).reduce((sum, c) => sum + parseFloat(c.amount), 0).toFixed(2);
      const totalSales = orders2.filter((o) => o.status === "completed").length;
      const conversionRate = "85%";
      res.json({ totalCommissions, pendingPayouts, totalSales, conversionRate });
    } catch (error) {
      console.error("Error fetching agent stats:", error);
      res.status(500).json({ message: "Failed to fetch agent stats" });
    }
  });
  app2.get("/api/analytics/sales", isAuthenticated, async (req, res) => {
    try {
      const data = [
        { date: "Mon", sales: 12, commissions: 24 },
        { date: "Tue", sales: 19, commissions: 38 },
        { date: "Wed", sales: 15, commissions: 30 },
        { date: "Thu", sales: 25, commissions: 50 },
        { date: "Fri", sales: 22, commissions: 44 },
        { date: "Sat", sales: 30, commissions: 60 },
        { date: "Sun", sales: 18, commissions: 36 }
      ];
      res.json(data);
    } catch (error) {
      console.error("Error fetching analytics:", error);
      res.status(500).json({ message: "Failed to fetch analytics" });
    }
  });
  app2.get("/api/analytics/top-customers", isAuthenticated, async (req, res) => {
    try {
      const data = [
        { id: "1", name: "John Doe", totalSpent: "450.00", orders: 15 },
        { id: "2", name: "Jane Smith", totalSpent: "380.00", orders: 12 },
        { id: "3", name: "Bob Johnson", totalSpent: "320.00", orders: 10 }
      ];
      res.json(data);
    } catch (error) {
      console.error("Error fetching top customers:", error);
      res.status(500).json({ message: "Failed to fetch top customers" });
    }
  });
  app2.get("/api/admin/users", isAuthenticated, async (req, res) => {
    try {
      const users2 = await storage.getAllUsers();
      res.json(users2);
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });
  app2.patch("/api/admin/users", isAuthenticated, async (req, res) => {
    try {
      const { userId, role } = req.body;
      await storage.updateUserRole(userId, role);
      res.json({ success: true });
    } catch (error) {
      console.error("Error updating user:", error);
      res.status(500).json({ message: "Failed to update user" });
    }
  });
  app2.get("/api/admin/bundles", isAuthenticated, async (req, res) => {
    try {
      const bundles2 = await storage.getBundles();
      res.json(bundles2);
    } catch (error) {
      console.error("Error fetching bundles:", error);
      res.status(500).json({ message: "Failed to fetch bundles" });
    }
  });
  app2.post("/api/admin/bundles", isAuthenticated, async (req, res) => {
    try {
      const bundle = await storage.createBundle(req.body);
      res.json(bundle);
    } catch (error) {
      console.error("Error creating bundle:", error);
      res.status(500).json({ message: "Failed to create bundle" });
    }
  });
  app2.get("/api/admin/logs", isAuthenticated, async (req, res) => {
    try {
      const logs = await storage.getApiLogs(50);
      res.json(logs);
    } catch (error) {
      console.error("Error fetching logs:", error);
      res.status(500).json({ message: "Failed to fetch logs" });
    }
  });
  app2.get("/api/admin/config", isAuthenticated, async (req, res) => {
    try {
      const primaryApi = await storage.getSystemConfig("primaryApiEnabled");
      const backupApi = await storage.getSystemConfig("backupApiEnabled");
      const slowDelivery = await storage.getSystemConfig("slowDeliveryTest");
      res.json({
        primaryApiEnabled: primaryApi?.value ?? true,
        backupApiEnabled: backupApi?.value ?? true,
        slowDeliveryTest: slowDelivery?.value ?? false
      });
    } catch (error) {
      console.error("Error fetching config:", error);
      res.status(500).json({ message: "Failed to fetch config" });
    }
  });
  app2.patch("/api/admin/config", isAuthenticated, async (req, res) => {
    try {
      const { key, value } = req.body;
      await storage.updateSystemConfig(key, value);
      if (key === "slowDeliveryTest") {
        mockProvider.setSlowDelivery(value);
      } else if (key === "primaryApiEnabled") {
        config.primaryProviderEnabled = value;
      } else if (key === "backupApiEnabled") {
        config.backupProviderEnabled = value;
      }
      res.json({ success: true });
    } catch (error) {
      console.error("Error updating config:", error);
      res.status(500).json({ message: "Failed to update config" });
    }
  });
  app2.patch("/api/user/profile", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const { firstName, lastName, email } = req.body;
      await storage.upsertUser({
        id: userId,
        firstName,
        lastName,
        email
      });
      res.json({ success: true });
    } catch (error) {
      console.error("Error updating profile:", error);
      res.status(500).json({ message: "Failed to update profile" });
    }
  });
  app2.post("/api/user/change-password", isAuthenticated, async (req, res) => {
    try {
      res.json({ success: true });
    } catch (error) {
      console.error("Error changing password:", error);
      res.status(500).json({ message: "Failed to change password" });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      ),
      await import("@replit/vite-plugin-dev-banner").then(
        (m) => m.devBanner()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    allowedHosts: true,
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json({
  verify: (req, _res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = parseInt(process.env.PORT || "5000", 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log(`serving on port ${port}`);
  });
})();
