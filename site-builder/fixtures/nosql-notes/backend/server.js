const express = require("express");
const crypto = require("crypto");
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, ScanCommand, DeleteCommand } =
  require("@aws-sdk/lib-dynamodb");

const app = express();
app.use(express.json());
const db = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const TABLE = process.env.TABLE_NOTES;

app.get("/api/health", (req, res) => res.json({ ok: true }));
app.get("/api/notes", async (req, res) => {
  const out = await db.send(new ScanCommand({ TableName: TABLE }));
  res.json(out.Items || []);
});
app.post("/api/notes", async (req, res) => {
  // x-user-name 是 URL 编码的（HTTP 头不能携带中文），必须解码后再用或存；
  // x-user-email 是 ASCII，平台不编码它。忘记解码不会报错，只会把
  // %E5%BD%AD 这类编码串存进数据——合同校验器会在部署前拦下。
  const item = { id: crypto.randomUUID(), text: req.body.text,
                 author: req.headers["x-user-email"] || "anonymous",
                 author_name: decodeURIComponent(req.headers["x-user-name"] || ""),
                 created_at: new Date().toISOString() };
  await db.send(new PutCommand({ TableName: TABLE, Item: item }));
  res.status(201).json(item);
});
app.delete("/api/notes/:id", async (req, res) => {
  await db.send(new DeleteCommand({ TableName: TABLE, Key: { id: req.params.id } }));
  res.status(204).end();
});
app.listen(process.env.PORT || 8080);
