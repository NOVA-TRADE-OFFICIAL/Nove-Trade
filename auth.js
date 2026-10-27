const express = require("express");
const bcrypt = require("bcryptjs");
const db = require("./db");

const router = express.Router();

function getPublicUser(user) {
  return {
    id: user.id,
    fullName: user.full_name,
    email: user.email,
    role: user.role,
    status: user.status,
    balance: user.balance ?? 0,
    currency: user.currency ?? "USDT"
  };
}

router.post("/signup", async (req, res) => {
  try {
    const { fullName, email, password } = req.body || {};

    if (
      typeof fullName !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Name, email and password are required."
      });
    }

    const cleanName = fullName.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 80) {
      return res.status(400).json({
        error: "Name must be between 2 and 80 characters."
      });
    }

    if (
      cleanEmail.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
    ) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    if (password.length < 12 || password.length > 128) {
      return res.status(400).json({
        error: "Password must be 12–128 characters."
      });
    }

    const existing = db.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).get(cleanEmail);

    if (existing) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const createAccount = db.transaction(() => {
      const result = db.prepare(`
        INSERT INTO users (
          full_name, email, password_hash, status, email_verified
        )
        VALUES (?, ?, ?, 'active', 1)
      `).run(cleanName, cleanEmail, passwordHash);

      const userId = Number(result.lastInsertRowid);

      db.prepare(`
        INSERT INTO wallets (user_id, balance, currency)
        VALUES (?, 0, 'USDT')
      `).run(userId);

      db.prepare(`
        INSERT INTO audit_logs (user_id, action)
        VALUES (?, 'account_created')
      `).run(userId);

      return userId;
    });

    const userId = createAccount();

    return res.status(201).json({
      message: "Account created successfully. You can now log in.",
      user: {
        id: userId,
        fullName: cleanName,
        email: cleanEmail,
        role: "user",
        status: "active",
        balance: 0,
        currency: "USDT"
      }
    });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    console.error("Signup error:", error.message);

    return res.status(500).json({
      error: "Could not create account."
    });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const user = db.prepare(`
      SELECT
        u.id,
        u.full_name,
        u.email,
        u.password_hash,
        u.role,
        u.status,
        w.balance,
        w.currency
      FROM users u
      LEFT JOIN wallets w ON w.user_id = u.id
      WHERE u.email = ?
    `).get(email.trim().toLowerCase());

    if (
      !user ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    if (user.status !== "active") {
      return res.status(403).json({
        error: "Your account is not active. Please contact support."
      });
    }

    if (!req.session) {
      return res.status(500).json({
        error: "Session middleware is not configured."
      });
    }

    req.session.regenerate((error) => {
      if (error) {
        console.error("Session regeneration error:", error.message);
        return res.status(500).json({
          error: "Could not start login session."
        });
      }

      req.session.userId = user.id;

      req.session.save((saveError) => {
        if (saveError) {
          console.error("Session save error:", saveError.message);
          return res.status(500).json({
            error: "Could not save login session."
          });
        }

        db.prepare(`
          INSERT INTO audit_logs (user_id, action)
          VALUES (?, 'login_success')
        `).run(user.id);

        return res.json({
          message: "Login successful.",
          user: getPublicUser(user)
        });
      });
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      error: "Could not log in."
    });
  }
});

router.get("/me", (req, res) => {
  if (!req.session?.userId) {
    return res.status(401).json({
      error: "Please log in."
    });
  }

  const user = db.prepare(`
    SELECT
      u.id,
      u.full_name,
      u.email,
      u.role,
      u.status,
      w.balance,
      w.currency
    FROM users u
    LEFT JOIN wallets w ON w.user_id = u.id
    WHERE u.id = ?
  `).get(req.session.userId);

  if (!user || user.status !== "active") {
    return req.session.destroy(() => {
      res.status(401).json({
        error: "Your session is no longer valid. Please log in again."
      });
    });
  }

  return res.json({
    user: getPublicUser(user)
  });
});

router.post("/logout", (req, res) => {
  if (!req.session) {
    return res.json({ message: "Logged out." });
  }

  req.session.destroy((error) => {
    if (error) {
      console.error("Logout error:", error.message);
      return res.status(500).json({
        error: "Could not log out."
      });
    }

    res.clearCookie("novatrade.sid", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax"
    });

    return res.json({
      message: "Logged out successfully."
    });
  });
});

module.exports = router;