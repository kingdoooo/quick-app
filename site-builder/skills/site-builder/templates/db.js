// DSQL 连接模板——站点代码不改此文件。
// 非 admin：用本站点专属 PG role（DSQL_USER）+ 普通 DbConnect token，
// 只被 GRANT 本站点 schema——数据隔离由平台在部署时配置。
const { Pool } = require("pg");
const { DsqlSigner } = require("@aws-sdk/dsql-signer");

const HOST = process.env.DSQL_ENDPOINT;
const SCHEMA = process.env.DSQL_SCHEMA;
const USER = process.env.DSQL_USER;

async function makePool() {
  const signer = new DsqlSigner({ hostname: HOST, region: "us-east-1" });
  const pool = new Pool({
    host: HOST, database: "postgres", user: USER,
    password: () => signer.getDbConnectAuthToken(),  // 非 admin token
    ssl: { rejectUnauthorized: true }, max: 3,
    maxLifetimeSeconds: 3300,  // token 有效期内轮换连接
  });
  pool.on("connect", c => c.query(`SET search_path = "${SCHEMA}"`));
  return pool;
}
module.exports = { makePool };
