---
status: accepted
date: 2026-09-02
---
# Lambda@Edge 的 RS256 验签用 vendored `cryptography`，不手写 RSA

Edge 函数原本只用标准库，直觉是继续手写一个百行的 RS256 验签（纯 Python 原型 0.24 ms/次）。
但 spec §5 RSA 原语层的那一整套 PKCS1 v1.5 陷阱（整块定时比较、整数范围、Bleichenbacher 类
伪造）加上证明它们真会红的变形测试，是我们自己永久背的审计面；而平台的 signer（auth）与 MCP
已经在锁定清单里信任 `cryptography==50.0.0`，"新增供应链依赖"只对 Edge 这一个部署单元成立。
真正未知的只有冷启动，于是事先写死判据再实测。

判据是**冷路径总时延**（Init 差加冷调用 handler 差）中位数 ≤ 300 ms、p95 ≤ 600 ms，被测函数
必须是最终形态（公钥模块顶层加载并预热）。第一轮 spike 只看了 Init 差且把 PEM 解析放在 handler
里，按总时延重算 128 MB 是 300.14 ms，判读作废。最终形态复测：128 MB 总差中位数 +143.3 ms /
p95 +147.1 ms，256 MB 与之无差，热调用验签增量 0.12 ms。决定 vendored `cryptography`，Edge
维持 128 MB，manylinux x86_64 交叉装、hash 钉死、不引 Docker。

## Consequences

- Edge 部署包从 1 个文件变成约 15.8 MB 解压 / 172 个文件，在 Lambda@Edge 50 MB 上限之内。
- 公钥必须在模块顶层加载并预热一次验签：这一步是总差从 300 ms 降到 143 ms 的全部原因，
  Edge 单测要断言 handler 路径里没有 `load_pem_public_key`。
- `--require-hashes` 的 AST 守卫要从 deployer bundling 扩到 `router/infrastructure/stack.py`。
- JOSE 层检查（规范 base64url、拒 `crit`、`alg` 只比对 allowlist、签名长度等于模长）与实现选择无关，照样要做。
- 若日后要撤回，spec §5 RSA 原语层的条款与反例清单仍在，那是唯一可接受的替代实现。

出处：`docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md` §11.1、§12；
脚本 `site-builder/scripts/spike_edge_crypto_coldstart.py`。
