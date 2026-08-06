/**
 * 首次 OAuth 授权（RFC 9728 Protected Resource Metadata 发现 + PKCE）。
 * 用法: node auth.js <endpoint_url> <client_id>
 * 浏览器完成飞书登录后，token 存 ~/.site-builder-deploy-token.json，
 * 之后 index.js 代理自动续期，正常只需跑一次。
 *
 * 发现链（实测）：endpoint 401 的 WWW-Authenticate → resource metadata →
 * authorization_servers → openid-configuration → authorize/token endpoint。
 * 注意：AgentCore 的 WWW-Authenticate 是 `Bearer resource_metadata="..."`
 * 形态（等号后带引号、Bearer 后可能无空格）；scope 只能请求 client 配置过的
 * `openid email`（多要 profile/phone 会 invalid_scope）。
 * 仅用 Node 内置模块（Node 18+）。浏览器打开用 macOS `open`，其他平台手动复制 URL。
 */

import http from 'http';
import { URL } from 'url';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { exec } from 'child_process';

const ENDPOINT = process.argv[2] || process.env.SITE_BUILDER_MCP_ENDPOINT;
const CLIENT_ID = process.argv[3] || process.env.SITE_BUILDER_MCP_CLIENT_ID;
if (!ENDPOINT || !CLIENT_ID) {
  console.error('用法: node auth.js <endpoint_url> <client_id>');
  process.exit(1);
}
// 18765 必须与 Cognito client 预注册的回调一致（8765/8766 被 Quick Desktop 占用）
const CALLBACK_PORT = 18765;
const TOKEN_PATH = path.join(process.env.HOME, '.site-builder-deploy-token.json');

/**
 * 原子且仅本人可读地写 token 文件。
 *
 * 两个都是实测确认的问题（Codex 审查 2026-08-06 P1）：
 * ① 裸 writeFileSync 不给 mode，在常见 umask 022 下文件是 **0644**——同机
 *    其他用户可读 refresh token。mcp client 是 public（无 secret），拿到
 *    refresh token 只需公开的 client ID 就能持续换 access token，以受害者身份
 *    部署、改权限、下线站点。当前 refresh 有效期 1 天，不是一次性泄漏。
 *    注意 mode 会被 umask 削减但不会被放宽，且**已存在的文件 mode 不变**，
 *    所以写完显式 chmod 一次（修复已泄漏的旧文件）。
 * ② 直接覆写不是原子的：两个代理进程并发刷新、或写入中途崩溃，会留下截断的
 *    JSON，下次启动解析失败即等于丢失授权。改为写临时文件再 rename（同目录，
 *    保证同一文件系统，rename 才是原子的）。
 */
function writeTokenFile(tokenPath, obj) {
  const tmp = `${tokenPath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, tokenPath);
  fs.chmodSync(tokenPath, 0o600);
}


async function discoverOAuth() {
  console.log('  Step 1: 从 401 的 WWW-Authenticate 取 resource metadata URL...');
  const challenge = await fetch(ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
  const wwwAuth = challenge.headers.get('www-authenticate') || '';
  const urlMatch = wwwAuth.match(/[Bb]earer\s*.*?"(https?:\/\/[^"]+)"/);
  if (!urlMatch) throw new Error(`无法解析 resource metadata URL: ${wwwAuth}`);

  console.log('  Step 2: 取 protected resource metadata...');
  const resourceMeta = await (await fetch(urlMatch[1])).json();
  const authServer = (resourceMeta.authorization_servers || [])[0];
  if (!authServer) throw new Error('resource metadata 中无 authorization_servers');

  console.log(`  Step 3: 取 auth server metadata（${authServer}）...`);
  const base = authServer.replace(/\/$/, '');
  for (const wellKnown of ['oauth-authorization-server', 'openid-configuration']) {
    const resp = await fetch(`${base}/.well-known/${wellKnown}`);
    if (resp.ok) return await resp.json();
  }
  throw new Error(`无法获取 ${authServer} 的 metadata`);
}

async function main() {
  console.log('🔐 site-builder-deploy OAuth 授权\n');
  const meta = await discoverOAuth();
  const { authorization_endpoint: authEndpoint, token_endpoint: tokenEndpoint } = meta;
  if (!authEndpoint || !tokenEndpoint) {
    throw new Error(`metadata 缺 endpoint: ${JSON.stringify(meta)}`);
  }
  console.log(`\n  authorize: ${authEndpoint}\n  token:     ${tokenEndpoint}`);

  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  const state = crypto.randomBytes(16).toString('hex');
  const redirectUri = `http://localhost:${CALLBACK_PORT}/callback`;

  const authUrl = new URL(authEndpoint);
  for (const [k, v] of Object.entries({
    client_id: CLIENT_ID, redirect_uri: redirectUri, response_type: 'code',
    state, code_challenge: codeChallenge, code_challenge_method: 'S256',
    scope: 'openid email',
  })) authUrl.searchParams.set(k, v);

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${CALLBACK_PORT}`);
    if (url.pathname !== '/callback') { res.writeHead(404); res.end(); return; }

    const err = url.searchParams.get('error');
    if (err) {
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<h1>❌ 授权失败</h1><p>${err}: ${url.searchParams.get('error_description') || ''}</p>`);
      setTimeout(() => process.exit(1), 500);
      return;
    }
    const code = url.searchParams.get('code');
    if (!code || url.searchParams.get('state') !== state) {
      res.writeHead(400); res.end('missing code / state mismatch');
      return;
    }

    const tokenData = await (await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', client_id: CLIENT_ID,
        code, redirect_uri: redirectUri, code_verifier: codeVerifier,
      }),
    })).json();

    if (!tokenData.access_token) {
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<h1>❌ token 交换失败</h1><pre>${JSON.stringify(tokenData, null, 2)}</pre>`);
      setTimeout(() => process.exit(1), 1000);
      return;
    }
    writeTokenFile(TOKEN_PATH, {
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token || null,
      token_endpoint: tokenEndpoint,
      expires_at: tokenData.expires_in ? Date.now() + tokenData.expires_in * 1000 : null,
    });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<h1>✅ 授权成功</h1><p>可以关闭此页面，token 已保存。</p>');
    console.log(`\n✅ token 已保存: ${TOKEN_PATH}`);
    setTimeout(() => process.exit(0), 1000);
  });

  server.listen(CALLBACK_PORT, () => {
    console.log(`\n👉 浏览器完成飞书登录：\n   ${authUrl}\n`);
    exec(`open "${authUrl}"`, (e) => {
      if (e) console.log('（无法自动打开浏览器，手动复制上面的链接）');
    });
  });
}

main().catch((e) => { console.error('❌', e.message); process.exit(1); });
