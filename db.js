const Database = require("better-sqlite3");
const path = require("path");
require("dotenv").config();

const dbPath = path.resolve(
  process.env.DATABASE_PATH || "./novatrade.db"
);

const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
      CHECK (role IN ('user', 'admin')),
    status TEXT NOT NULL DEFAULT 'active'
      CHECK (status IN ('pending', 'active', 'suspended')),
    email_verified INTEGER NOT NULL DEFAULT 1
      CHECK (email_verified IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS wallets (
    user_id INTEGER PRIMARY KEY,
    balance REAL NOT NULL DEFAULT 0 CHECK (balance >= 0),
    currency TEXT NOT NULL DEFAULT 'USDT',
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS deposits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    provider TEXT NOT NULL DEFAULT 'plisio',
    invoice_id TEXT UNIQUE,
    txn_id TEXT UNIQUE,
    amount REAL NOT NULL CHECK (amount > 0),
    currency TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'completed', 'failed', 'expired')),
    payment_url TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    paid_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    deposit_id INTEGER UNIQUE,
    type TEXT NOT NULL
      CHECK (type IN ('deposit', 'withdrawal', 'trade', 'adjustment')),
    amount REAL NOT NULL CHECK (amount > 0),
    currency TEXT NOT NULL DEFAULT 'USDT',
    status TEXT NOT NULL DEFAULT 'completed',
    description TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (deposit_id) REFERENCES deposits(id)
  );

  CREATE INDEX IF NOT EXISTS idx_deposits_user
    ON deposits(user_id, created_at);

  CREATE INDEX IF NOT EXISTS idx_transactions_user
    ON transactions(user_id, created_at);
`);

console.log("NovaTrade database initialized.");

module.exports = db;