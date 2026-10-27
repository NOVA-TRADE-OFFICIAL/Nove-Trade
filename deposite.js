const express = require("express");
const crypto = require("crypto");
const db = require("./db");

const router = express.Router();

const ALLOWED_ASSETS = new Set(["USDT_TRX", "TRX"]);
const MIN_DEPOSIT_USD = 10;
const MAX_DEPOSIT_USD = 10000;

function verifyPlisioCallback(data, secret) {
  if (
    !data ||
    typeof data !== "object" ||
    Array.isArray(data) ||
    typeof data.verify_hash !== "string"
  ) {
    return false;
  }

  const suppliedHash = data.verify_hash;
  const payload = { ...data };
  delete payload.verify_hash;

  const expectedHash = crypto
    .createHmac("sha1", secret)
    .update(JSON.stringify(payload))
    .digest();

  let receivedHash;

  try {
    receivedHash = Buffer.from(suppliedHash, "hex");
  } catch {
    return false;
  }

  return (
    receivedHash.length === expectedHash.length &&
    crypto.timingSafeEqual(receivedHash, expectedHash)
  );
}

// Create an invoice for a logged-in user.
router.post("/create", async (req, res) => {
  try {
    const userId = req.session?.userId;

    if (!userId) {
      return res.status(401).json({ error: "Please log in first." });
    }

    const { amount, asset } = req.body || {};
    const numericAmount = Number(amount);

    if (
      !Number.isFinite(numericAmount) ||
      Math.round(numericAmount * 100) !== numericAmount * 100 ||
      numericAmount < MIN_DEPOSIT_USD ||
      numericAmount > MAX_DEPOSIT_USD
    ) {
      return res.status(400).json({
        error: "Deposit must be between $10 and $10,000 USD."
      });
    }

    if (!ALLOWED_ASSETS.has(asset)) {
      return res.status(400).json({
        error: "Choose USDT TRC-20 or TRX."
      });
    }

    const apiKey = process.env.PLISIO_API_KEY;
    const publicBaseUrl = process.env.PUBLIC_BASE_URL;

    if (!apiKey || !publicBaseUrl) {
      return res.status(503).json({
        error: "Payment configuration is incomplete."
      });
    }

    const baseUrl = new URL(publicBaseUrl);

    if (
      baseUrl.protocol !== "https:" ||
      baseUrl.username ||
      baseUrl.password
    ) {
      return res.status(503).json({
        error: "A valid public HTTPS backend URL is required."
      });
    }

    const user = db.prepare(`
      SELECT id, status
      FROM users
      WHERE id = ?
    `).get(userId);

    if (!user || user.status !== "active") {
      return res.status(403).json({
        error: "Your account is not active."
      });
    }

    const insert = db.prepare(`
      INSERT INTO deposits (user_id, amount, currency, status)
      VALUES (?, ?, ?, 'pending')
    `).run(userId, numericAmount, asset);

    const depositId = Number(insert.lastInsertRowid);

    const callbackUrl = new URL(
      "/api/deposits/callback?json=true",
      baseUrl
    ).toString();

    const params = new URLSearchParams({
      api_key: apiKey,
      order_name: `NovaTrade Deposit ${depositId}`,
      order_number: String(depositId),
      source_currency: "USD",
      source_amount: numericAmount.toFixed(2),
      currency: asset,
      allowed_psys_cids: asset,
      description: `NovaTrade wallet deposit ${depositId}`,
      callback_url: callbackUrl,
      expire_min: "30"
    });

    const response = await fetch(
      `https://api.plisio.net/api/v1/invoices/new?${params}`,
      { signal: AbortSignal.timeout(15000) }
    );

    const result = await response.json();

    if (
      !response.ok ||
      result.status !== "success" ||
      !result.data?.txn_id ||
      !result.data?.invoice_url
    ) {
      db.prepare(`
        UPDATE deposits SET status = 'failed'
        WHERE id = ? AND status = 'pending'
      `).run(depositId);

      console.error("Plisio invoice creation failed.");
      return res.status(502).json({
        error: "Could not create a payment invoice. Please try again."
      });
    }

    db.prepare(`
      UPDATE deposits
      SET invoice_id = ?, payment_url = ?
      WHERE id = ? AND status = 'pending'
    `).run(
      String(result.data.txn_id),
      String(result.data.invoice_url),
      depositId
    );

    return res.status(201).json({
      message: "Payment invoice created.",
      depositId,
      amount: numericAmount,
      currency: "USDT",
      paymentAsset: asset,
      paymentUrl: result.data.invoice_url,
      status: "pending"
    });
  } catch (error) {
    console.error("Deposit creation error:", error.message);

    return res.status(500).json({
      error: "Could not create deposit."
    });
  }
});

// Plisio sends JSON when callback_url contains ?json=true.
router.post("/callback", (req, res) => {
  try {
    const secret = process.env.PLISIO_API_KEY;
    const data = req.body;

    if (!secret || !verifyPlisioCallback(data, secret)) {
      return res.status(403).json({
        error: "Invalid payment callback signature."
      });
    }

    if (
      data.ipn_type !== "invoice" ||
      typeof data.order_number !== "string" ||
      typeof data.txn_id !== "string" ||
      typeof data.status !== "string"
    ) {
      return res.status(400).json({
        error: "Invalid invoice callback."
      });
    }

    const depositId = Number(data.order_number);

    if (!Number.isSafeInteger(depositId) || depositId < 1) {
      return res.status(400).json({
        error: "Invalid order number."
      });
    }

    const deposit = db.prepare(`
      SELECT *
      FROM deposits
      WHERE id = ?
    `).get(depositId);

    if (!deposit) {
      return res.status(404).json({
        error: "Deposit not found."
      });
    }

    if (deposit.status === "completed") {
      return res.json({ received: true });
    }

    if (
      !deposit.invoice_id ||
      deposit.invoice_id !== data.txn_id
    ) {
      return res.status(400).json({
        error: "Invoice ID mismatch."
      });
    }

    if (data.status !== "completed") {
      const allowedStatuses = new Set([
        "new",
        "pending",
        "expired",
        "cancelled",
        "error"
      ]);

      if (allowedStatuses.has(data.status)) {
        db.prepare(`
          UPDATE deposits
          SET status = ?
          WHERE id = ? AND status = 'pending'
        `).run(
          data.status === "new" || data.status === "pending"
            ? "pending"
            : data.status === "expired"
              ? "expired"
              : "failed",
          depositId
        );
      }

      return res.json({ received: true });
    }

    const paidAmount = Number(data.source_amount);
    const receivedCurrency = String(data.currency || "");
    const receivedAsset = String(data.psys_cid || receivedCurrency);

    if (
      !Number.isFinite(paidAmount) ||
      Math.abs(paidAmount - deposit.amount) > 0.01 ||
      data.source_currency !== "USD" ||
      receivedAsset !== deposit.currency ||
      Number(data.confirmations) < 1
    ) {
      return res.status(400).json({
        error: "Payment details do not match the invoice."
      });
    }

    const creditDeposit = db.transaction(() => {
      const current = db.prepare(`
        SELECT status
        FROM deposits
        WHERE id = ?
      `).get(depositId);

      if (!current || current.status === "completed") {
        return;
      }

      const update = db.prepare(`
        UPDATE deposits
        SET status = 'completed',
            txn_id = ?,
            paid_at = CURRENT_TIMESTAMP
        WHERE id = ? AND status = 'pending'
      `).run(data.txn_id, depositId);

      if (update.changes !== 1) {
        return;
      }

      db.prepare(`
        UPDATE wallets
        SET balance = balance + ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
      `).run(deposit.amount, deposit.user_id);

      db.prepare(`
        INSERT INTO transactions (
          user_id, deposit_id, type, amount, currency,
          status, description
        )
        VALUES (?, ?, 'deposit', ?, 'USDT',
                'completed', ?)
      `).run(
        deposit.user_id,
        depositId,
        deposit.amount,
        `Verified Plisio deposit ${depositId}`
      );

      db.prepare(`
        INSERT INTO audit_logs (user_id, action)
        VALUES (?, ?)
      `).run(deposit.user_id, `deposit_completed_${depositId}`);
    });

    creditDeposit();

    return res.json({ received: true });
  } catch (error) {
    console.error("Plisio callback error:", error.message);

    return res.status(500).json({
      error: "Could not process payment callback."
    });
  }
});

module.exports = router;