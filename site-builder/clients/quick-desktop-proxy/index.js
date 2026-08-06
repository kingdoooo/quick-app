/**
 * site-builder-deploy MCP stdio 代理
 *
 * 为什么存在：Quick Desktop 的 Remote MCP 只支持静态 Headers，不支持 OAuth
 * 授权码流程（2026-07-29 实测，直接填 endpoint 报 401）。本代理以 Local MCP
 * （stdio）形态接入 Quick Desktop，透明转发 JSON-RPC 到 AgentCore endpoint，
 * 自动注入并刷新 Bearer token。首次授权先跑 `node auth.js <endpoint> <client_id>`。
 *
 * 用法（Quick Desktop → Settings → Capabilities → MCP → Add，Connection type=Local）：
 *   Command: node
 *   Args:    /绝对路径/index.js <endpoint_url> <client_id>
 *
 * 仅用 Node 内置模块（需 Node 18+ 的全局 fetch），无需 npm install。
 * 适用于任何"OAuth 保护的 Remote MCP + 只支持静态头的客户端"场景。
 */

import fs from 'fs';
import path from 'path';
import { createInterface } from 'readline';

const ENDPOINT = process.argv[2] || process.env.SITE_BUILDER_MCP_ENDPOINT;
const CLIENT_ID = process.argv[3] || process.env.SITE_BUILDER_MCP_CLIENT_ID;
if (!ENDPOINT || !CLIENT_ID) {
  process.stderr.write('用法: node index.js <endpoint_url> <client_id>\n');
  process.exit(1);
}
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


// --- token 管理 ---

function loadToken() {
  try {
    return JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf-8'));
  } catch {
    return null;
  }
}

async function refreshToken(tokenData) {
  if (!tokenData.refresh_token || !tokenData.token_endpoint) return null;
  try {
    const resp = await fetch(tokenData.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        refresh_token: tokenData.refresh_token,
      }),
    });
    if (!resp.ok) return null;
    const fresh = await resp.json();
    const updated = {
      ...tokenData,
      access_token: fresh.access_token,
      refresh_token: fresh.refresh_token || tokenData.refresh_token,
      expires_at: fresh.expires_in ? Date.now() + fresh.expires_in * 1000
                                   : tokenData.expires_at,
    };
    writeTokenFile(TOKEN_PATH, updated);
    return updated;
  } catch {
    return null;
  }
}

async function getValidToken() {
  let tokenData = loadToken();
  if (!tokenData) {
    throw new Error(`未找到 token（${TOKEN_PATH}）。先运行 node auth.js 完成 OAuth 登录。`);
  }
  // 过期前 5 分钟主动刷新
  if (tokenData.expires_at && Date.now() > tokenData.expires_at - 300_000) {
    tokenData = await refreshToken(tokenData);
    if (!tokenData) {
      throw new Error('token 过期且刷新失败。重新运行 node auth.js 授权。');
    }
  }
  return tokenData.access_token;
}

// --- stdio ⇄ streamable-http 桥 ---

let remoteSessionId = null;

async function forwardToRemote(message) {
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${await getValidToken()}`,
    'Accept': 'application/json, text/event-stream',
  };
  if (remoteSessionId) headers['Mcp-Session-Id'] = remoteSessionId;

  const resp = await fetch(ENDPOINT, {
    method: 'POST', headers, body: JSON.stringify(message),
  });
  const sessionId = resp.headers.get('mcp-session-id');
  if (sessionId) remoteSessionId = sessionId;

  if (!resp.ok) {
    throw new Error(`Remote MCP error ${resp.status}: ${await resp.text()}`);
  }

  const contentType = resp.headers.get('content-type') || '';
  if (contentType.includes('text/event-stream')) {
    const results = [];
    for (const line of (await resp.text()).split('\n')) {
      if (line.startsWith('data: ')) {
        try { results.push(JSON.parse(line.slice(6))); } catch {}
      }
    }
    return results;
  }
  const data = await resp.json();
  return Array.isArray(data) ? data : [data];
}

function writeMessage(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

async function handleMessage(message) {
  try {
    for (const resp of await forwardToRemote(message)) writeMessage(resp);
  } catch (e) {
    if (message.id !== undefined) {
      writeMessage({ jsonrpc: '2.0', id: message.id,
                     error: { code: -32603, message: e.message } });
    } else {
      process.stderr.write(`[proxy error] ${e.message}\n`);
    }
  }
}

const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  line = line.trim();
  if (!line) return;
  try {
    handleMessage(JSON.parse(line));
  } catch (e) {
    process.stderr.write(`[parse error] ${e.message}\n`);
  }
});
rl.on('close', () => process.exit(0));

process.stderr.write('[site-builder-deploy-proxy] Ready (stdio mode)\n');
