const express = require("express");
const { makePool } = require("./db");

const app = express();
app.use(express.json());
let pool;
const db = async () => (pool ??= await makePool());

app.get("/api/health", (req, res) => res.json({ ok: true }));
app.get("/api/expenses", async (req, res) => {
  const { rows } = await (await db()).query(
    "SELECT * FROM expenses ORDER BY created_at DESC");
  res.json(rows);
});
app.post("/api/expenses", async (req, res) => {
  const { rows } = await (await db()).query(
    "INSERT INTO expenses (title, amount, spender) VALUES ($1,$2,$3) RETURNING *",
    [req.body.title, req.body.amount, req.headers["x-user-email"] || "anonymous"]);
  res.status(201).json(rows[0]);
});
app.listen(process.env.PORT || 8080);
