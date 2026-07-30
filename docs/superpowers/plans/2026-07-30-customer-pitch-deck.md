# 客户方案介绍 PPT（HTML）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 产出单文件 `docs/presentation/slides.html`——20 页深色主题 HTML PPT，面向潜在客户技术人员介绍 Quick Site Builder 方案（痛点/架构/安全/AWS 组件/成本/Manus 对比/路线图）。

**Architecture:** 一个自包含 HTML 文件：`<style>` 设计令牌 + 版式类，`<main id="deck">` 内 20 个 `<section class="slide">`，`<script>` 提供键盘/点击翻页、hash 跳页、scale 自适应，以及 `archDiagram(highlight)` 函数为 P4-P8 渲染同一张五层架构 SVG（当前层高亮）。旁挂一个 `check_slides.py` 校验脚本做自动化验收（页数/外部依赖/敏感值泄漏）。

**Tech Stack:** 纯 HTML/CSS/JS（无框架、无外部请求）、内联 SVG、Python3 校验脚本。

**Spec:** `docs/superpowers/specs/2026-07-30-customer-pitch-deck-design.md`（本计划所有文案与数字的唯一来源；冲突时以 spec 为准）

## Global Constraints

- 单文件 `docs/presentation/slides.html`，CSS/JS/SVG 全内联，**零外部请求**（无 `<script src>`、`<link href>`、`url(http…)`、外链 `<img>`）
- 16:9 固定画布 1280×720 基准，`transform: scale()` 自适应窗口
- 深色主题；中文无衬线字栈 `-apple-system, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Noto Sans CJK SC", sans-serif`；代码/URL 用 `"SF Mono", Menlo, Consolas, monospace`
- 中文为主，AWS 服务名/技术术语保留英文
- 域名一律用占位 `app-xxx.your-domain.com` / `your-domain.com`；**不得出现任何真实账号 ID、域名、证书 ARN**（check_slides.py 会拿 gitignored config.ini 的值反查）
- 翻页：←/→、Space、PgUp/PgDn、点击屏幕左右边缘；Home/End 跳首尾；右下角页码 `n/20`；URL hash `#5` 跳页且刷新保位
- 页面切换淡入即可，内容不做分步 build
- `@media print` 每页一张 A4 横版
- 图表颜色/形式遵循 dataviz skill（做 P14 柱状图前必须先 `Skill(dataviz)`）
- 每个任务结束 `git commit`（不带 `--no-verify`，让 pre-commit 扫描跑完）

## File Structure

| 文件 | 职责 |
|---|---|
| `docs/presentation/slides.html` | 交付物：20 页 PPT 单文件 |
| `docs/presentation/check_slides.py` | 验收脚本：页数=20、无外部资源、无 config.ini 真实值/12 位账号 ID |

---

### Task 1: 校验脚本 + 骨架与导航框架

**Files:**
- Create: `docs/presentation/check_slides.py`
- Create: `docs/presentation/slides.html`

**Interfaces:**
- Produces（后续任务全部依赖）：
  - CSS 类：`.slide`（一页）、`.eyebrow`（左上章节眉标）、`.takeaway`(底部结论行)、`.cols2`（两栏 grid）、`.card`（要点卡片）、`.num`（大数字强调）、`table` 默认深色样式、`code` 等宽
  - CSS 变量：`--bg --panel --text --muted --accent --line --ok`
  - 页结构约定：`<section class="slide" id="sN"><div class="eyebrow">章节</div><h1>标题</h1><div class="content">…</div><div class="takeaway">…</div></section>`，N=1..20 按 spec 页序
  - JS：`show(i)` 翻页、`fit()` 缩放（后续任务不需要改 JS）

- [ ] **Step 1: 写校验脚本（先行失败测试）**

```python
#!/usr/bin/env python3
"""验收 slides.html：页数 / 外部依赖 / 敏感值。exit 0 = 通过。"""
import re, sys, pathlib, configparser

here = pathlib.Path(__file__).parent
html_path = here / "slides.html"
if not html_path.exists():
    print("FAIL: slides.html 不存在"); sys.exit(1)
html = html_path.read_text(encoding="utf-8")
errors = []

n = len(re.findall(r'<section class="slide"', html))
if n != 20:
    errors.append(f"应有 20 页，实际 {n}")

for pat in (r'<script[^>]+\bsrc=', r'<link[^>]+\bhref=', r'url\(\s*[\'"]?https?:', r'<img[^>]+src=[\'"]https?:'):
    if re.search(pat, html):
        errors.append(f"发现外部资源引用: {pat}")

if re.search(r'\b\d{12}\b', html):
    errors.append("发现疑似 12 位 AWS 账号 ID")

# 反查 gitignored 配置里的真实值（域名/ARN/ID 等）是否泄漏进幻灯片
for rel in ("../../site-builder/config.ini", "../../router/config.ini"):
    cfg = (here / rel).resolve()
    if not cfg.exists():
        continue
    cp = configparser.ConfigParser()
    cp.read(cfg)
    for sec in cp.sections():
        for key, val in cp.items(sec):
            val = val.strip()
            if len(val) >= 6 and not val.startswith(("#", "http://localhost")) and val in html:
                errors.append(f"config 值泄漏: [{sec}] {key}（值不打印）")

for kw in ("pager", "location.hash", "@media print"):
    if kw not in html:
        errors.append(f"缺少必备特性标记: {kw}")

if errors:
    print("FAIL:"); [print(" -", e) for e in errors]; sys.exit(1)
print(f"PASS: 20 slides, no external deps, no leaked values")
```

- [ ] **Step 2: 运行确认失败**

Run: `python3 docs/presentation/check_slides.py`
Expected: `FAIL: slides.html 不存在`，exit 1

- [ ] **Step 3: 写骨架 slides.html**

设计令牌先按下列缺省写入（做 P14 图表的 Task 7 会经 dataviz skill 复核，若 palette 冲突以 dataviz 为准回改此处变量值即可，类名不变）：

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>Quick 自动化建站平台 — 方案介绍</title>
<style>
:root{
  --bg:#0F1318; --panel:#1A222C; --text:#E7ECF2; --muted:#9AA7B4;
  --accent:#4DA3FF; --line:#2A3542; --ok:#46C67C;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--text);
  font-family:-apple-system,"PingFang SC","Hiragino Sans GB","Microsoft YaHei","Noto Sans CJK SC",sans-serif;
  overflow:hidden}
code,.mono{font-family:"SF Mono",Menlo,Consolas,monospace;color:var(--accent)}
#stage{position:fixed;inset:0;display:flex;align-items:center;justify-content:center}
#deck{width:1280px;height:720px;position:relative;transform-origin:center center}
.slide{position:absolute;inset:0;padding:56px 72px;display:none;flex-direction:column;
  animation:fadein .25s ease}
.slide.active{display:flex}
@keyframes fadein{from{opacity:0}to{opacity:1}}
.eyebrow{font-size:15px;letter-spacing:.2em;color:var(--accent);margin-bottom:10px}
h1{font-size:40px;font-weight:700;margin-bottom:28px;line-height:1.25}
.content{flex:1;font-size:21px;line-height:1.65;min-height:0}
.takeaway{border-top:1px solid var(--line);padding-top:14px;font-size:20px;color:var(--accent)}
.cols2{display:grid;grid-template-columns:1fr 1fr;gap:28px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px 22px}
.card h3{font-size:20px;margin-bottom:8px;color:var(--text)}
.card p{font-size:17px;color:var(--muted)}
.num{font-size:44px;font-weight:700;color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:17px;line-height:1.5}
th,td{border:1px solid var(--line);padding:8px 12px;text-align:left;vertical-align:top}
th{background:var(--panel);color:var(--text);font-weight:600}
td{color:var(--muted)} td b,td strong{color:var(--text)}
.muted{color:var(--muted)} .ok{color:var(--ok)}
#pager{position:fixed;right:18px;bottom:12px;font-size:14px;color:var(--muted);z-index:9}
</style>
</head>
<body>
<div id="stage"><main id="deck">
  <!-- 20 页占位：Task 2-9 逐组替换 .content -->
  <!-- BEGIN SLIDES -->
  <section class="slide" id="s1"><div class="eyebrow">封面</div><h1>Quick 自动化建站平台</h1><div class="content"></div></section>
  <section class="slide" id="s2"><div class="eyebrow">痛点</div><h1>Agent 推广的“最后一站”</h1><div class="content"></div></section>
  <section class="slide" id="s3"><div class="eyebrow">方案</div><h1>一句“部署”，90 秒拿到可分享 URL</h1><div class="content"></div></section>
  <section class="slide" id="s4"><div class="eyebrow">架构</div><h1>五层架构总览</h1><div class="content"></div></section>
  <section class="slide" id="s5"><div class="eyebrow">架构 ①②</div><h1>建站 Skill + 部署 MCP：合同是锚点</h1><div class="content"></div></section>
  <section class="slide" id="s6"><div class="eyebrow">架构 ③</div><h1>异步执行器：Step Functions 流水线</h1><div class="content"></div></section>
  <section class="slide" id="s7"><div class="eyebrow">架构 ④</div><h1>路由与鉴权：全部在边缘</h1><div class="content"></div></section>
  <section class="slide" id="s8"><div class="eyebrow">架构 ⑤</div><h1>身份层：一套 Cognito，三处消费</h1><div class="content"></div></section>
  <section class="slide" id="s9"><div class="eyebrow">架构</div><h1>三档站点 Tier</h1><div class="content"></div></section>
  <section class="slide" id="s10"><div class="eyebrow">安全</div><h1>站点代码按不可信对待</h1><div class="content"></div></section>
  <section class="slide" id="s11"><div class="eyebrow">安全</div><h1>鉴权正确性：三个想清楚了的细节</h1><div class="content"></div></section>
  <section class="slide" id="s12"><div class="eyebrow">落地</div><h1>AWS 组件全景</h1><div class="content"></div></section>
  <section class="slide" id="s13"><div class="eyebrow">成本</div><h1>成本模型：假设与免费额度</h1><div class="content"></div></section>
  <section class="slide" id="s14"><div class="eyebrow">成本</div><h1>20 / 50 / 200 个 App 的月成本</h1><div class="content"></div></section>
  <section class="slide" id="s15"><div class="eyebrow">落地</div><h1>部署到你的账号需要什么</h1><div class="content"></div></section>
  <section class="slide" id="s16"><div class="eyebrow">对比</div><h1>部署体验：对齐 Manus 的流畅</h1><div class="content"></div></section>
  <section class="slide" id="s17"><div class="eyebrow">对比</div><h1>架构取舍：为什么解耦 Agent</h1><div class="content"></div></section>
  <section class="slide" id="s18"><div class="eyebrow">路线</div><h1>二期路线图</h1><div class="content"></div></section>
  <section class="slide" id="s19"><div class="eyebrow">总结</div><h1>三个核心主张</h1><div class="content"></div></section>
  <section class="slide" id="s20"><div class="eyebrow">附录</div><h1>测试、质量与文档</h1><div class="content"></div></section>
  <!-- END SLIDES -->
</main></div>
<div id="pager">1 / 20</div>
<script>
const slides=[...document.querySelectorAll('.slide')];let cur=-1;
function show(i){
  i=Math.max(0,Math.min(slides.length-1,i));if(i===cur)return;cur=i;
  slides.forEach((s,j)=>s.classList.toggle('active',j===cur));
  document.getElementById('pager').textContent=(cur+1)+' / '+slides.length;
  history.replaceState(null,'','#'+(cur+1));
}
function fit(){
  const s=Math.min(innerWidth/1280,innerHeight/720);
  document.getElementById('deck').style.transform='scale('+s+')';
}
addEventListener('keydown',e=>{
  if(['ArrowRight',' ','PageDown'].includes(e.key)){e.preventDefault();show(cur+1)}
  if(['ArrowLeft','PageUp'].includes(e.key)){e.preventDefault();show(cur-1)}
  if(e.key==='Home')show(0);
  if(e.key==='End')show(slides.length-1);
});
addEventListener('click',e=>{
  if(e.target.closest('a,button'))return;
  show(e.clientX<innerWidth*0.25?cur-1:(e.clientX>innerWidth*0.75?cur+1:cur));
});
addEventListener('hashchange',()=>show((parseInt(location.hash.slice(1))||1)-1));
addEventListener('resize',fit);
show((parseInt(location.hash.slice(1))||1)-1);fit();
</script>
</body>
</html>
```

- [ ] **Step 4: 运行校验通过 + 浏览器抽查**

Run: `python3 docs/presentation/check_slides.py` → Expected: PASS
Run: `open docs/presentation/slides.html`，确认：翻页键/边缘点击/页码/`#7` 跳页/缩放窗口不变形。

- [ ] **Step 5: Commit**

```bash
git add docs/presentation/slides.html docs/presentation/check_slides.py
git commit -m "feat(deck): skeleton, nav framework and acceptance checker for pitch deck"
```

---

### Task 2: 五层架构 SVG（archDiagram）+ P4 总览页

**Files:**
- Modify: `docs/presentation/slides.html`（`</script>` 前追加函数；填充 `#s4 .content`）

**Interfaces:**
- Consumes: Task 1 的页结构与 CSS 变量
- Produces: `archDiagram(highlight)` → 返回 SVG 字符串；`highlight` 取 0（全亮）或 1-5（高亮该层，其余压暗）。任何 `.content` 内放 `<div class="arch" data-arch="N"></div>` 即自动渲染（初始化循环在函数定义后执行）。Task 4 的 P5-P8 依赖此接口。

- [ ] **Step 1: 在 `<script>` 末尾（`show(...)` 初始化之前）加入 archDiagram 与渲染循环**

```js
function archDiagram(highlight){
  const layers=[
    {n:'①',t:'建站 Skill',d:'“部署合同”：site.json + 目录约定 + 代码红线 · Quick Desktop / Claude Code / Kiro 通用'},
    {n:'②',t:'部署 MCP',d:'AgentCore Runtime · 5 工具秒级返回 · OAuth 携带飞书身份'},
    {n:'③',t:'异步执行器',d:'Step Functions 流水线：校验 → 建库 → 构建 → 部署 → 原子切流 → 冒烟'},
    {n:'④',t:'路由 + 鉴权',d:'CloudFront *.your-domain.com + Lambda@Edge：查路由 → 验 JWT → 注入身份 → 分流'},
    {n:'⑤',t:'身份层',d:'Cognito 联邦飞书（可换任意标准 IdP）· 身份即邮箱'},
  ];
  const arrows=['MCP 调用（OAuth 带飞书身份）','条件迁移状态 + 启动 SFN','写路由表（subdomain → 目标 + auth 策略）','未登录 302 → 登录服务'];
  const W=1000,LH=74,GAP=34,X=60,BW=880;
  let svg=`<svg viewBox="0 0 ${W} ${5*LH+4*GAP+8}" width="100%" style="max-height:100%">`;
  layers.forEach((L,i)=>{
    const y=4+i*(LH+GAP);
    const on=!highlight||highlight===i+1;
    const op=on?1:0.28;
    const stroke=highlight===i+1?'var(--accent)':'var(--line)';
    const sw=highlight===i+1?2.5:1.2;
    svg+=`<g opacity="${op}">
      <rect x="${X}" y="${y}" width="${BW}" height="${LH}" rx="10" fill="var(--panel)" stroke="${stroke}" stroke-width="${sw}"/>
      <text x="${X+26}" y="${y+45}" font-size="26" fill="var(--accent)">${L.n}</text>
      <text x="${X+70}" y="${y+32}" font-size="21" font-weight="600" fill="var(--text)">${L.t}</text>
      <text x="${X+70}" y="${y+58}" font-size="15.5" fill="var(--muted)">${L.d}</text></g>`;
    if(i<4){
      const ay=y+LH;
      svg+=`<g opacity="${(!highlight||highlight===i+1||highlight===i+2)?1:0.28}">
        <line x1="${W/2}" y1="${ay}" x2="${W/2}" y2="${ay+GAP-8}" stroke="var(--muted)" stroke-width="1.5"/>
        <path d="M ${W/2-5} ${ay+GAP-12} L ${W/2} ${ay+GAP-4} L ${W/2+5} ${ay+GAP-12}" fill="none" stroke="var(--muted)" stroke-width="1.5"/>
        <text x="${W/2+16}" y="${ay+GAP/2+4}" font-size="14.5" fill="var(--muted)">${arrows[i]}</text></g>`;
    }
  });
  return svg+'</svg>';
}
document.querySelectorAll('[data-arch]').forEach(el=>{el.innerHTML=archDiagram(parseInt(el.dataset.arch));});
```

- [ ] **Step 2: 填充 P4（#s4 .content）**

```html
<div class="arch" data-arch="0" style="height:100%"></div>
```

并在 `#s4` 的 `</section>` 前加：
```html
<div class="takeaway">生成交给任意 Agent；平台只做 Agent 做不了的“安全落进企业云”——每一层都可独立替换。</div>
```

- [ ] **Step 3: 验证**

Run: `python3 docs/presentation/check_slides.py` → PASS
Run: `open docs/presentation/slides.html#4` → 五层图完整、箭头标签可读、无横向溢出。

- [ ] **Step 4: Commit**

```bash
git add docs/presentation/slides.html
git commit -m "feat(deck): reusable 5-layer architecture SVG and overview slide (P4)"
```

---

### Task 3: 开场三页（P1-P3）

**Files:**
- Modify: `docs/presentation/slides.html`（填充 `#s1 #s2 #s3` 的 `.content` 与 `.takeaway`）

**Interfaces:**
- Consumes: Task 1 的 `.cols2 .card .num` 等类

- [ ] **Step 1: P1 封面（#s1）**

`.content` 替换为（封面不加 takeaway，h1 后补副标题）：

```html
<div style="display:flex;flex-direction:column;justify-content:center;height:100%">
  <div style="font-size:56px;font-weight:700;line-height:1.3">Quick 自动化建站平台</div>
  <div style="font-size:26px;color:var(--muted);margin-top:18px">让业务人员的 Web App 自动部署到<b style="color:var(--text)">你自己的 AWS</b></div>
  <div style="margin-top:48px;font-size:19px;color:var(--muted)">
    <span class="ok">●</span> 已在真实 AWS 账号全量部署并端到端验证（154 单元测试 + E2E）
  </div>
  <div style="margin-top:10px;font-size:17px;color:var(--muted)">面向技术评估的方案介绍 · 2026</div>
</div>
```
同时把 `#s1` 内的 `<h1>Quick 自动化建站平台</h1>` 与眉标删除（封面无常规版式）。

- [ ] **Step 2: P2 痛点（#s2）**

```html
<div style="text-align:center;font-size:22px;margin-bottom:26px">
  Agent 已经能把内部工具的<b>代码完整写出来</b>——但离“同事能用”还差最后一站：
  <div class="mono" style="margin-top:14px;font-size:20px">代码已生成 ──▶ <span style="color:var(--muted)">？？？</span> ──▶ 员工可访问的内部应用</div>
</div>
<div class="cols2" style="grid-template-columns:1fr 1fr 1fr">
  <div class="card"><h3>① 部署门槛</h3><p>AWS 控制台、CI/CD、域名证书……不是业务人员的技能栈；每次都找开发排期，Agent 的效率优势被抵消。</p></div>
  <div class="card"><h3>② 运维成本</h3><p>每个小工具配一套基础设施（实例/数据库/网关）不现实——内部工具数量多、单个价值小、闲置时间长。</p></div>
  <div class="card"><h3>③ 权限失控</h3><p>内部数据的 App 不能公网裸奔；让业务人员自己配鉴权，等于没有鉴权。</p></div>
</div>
<div class="takeaway">最后一站没打通，Agent 生成的就只是“代码”，不是“应用”。</div>
```
（`.takeaway` 放 `.content` 之后、`</section>` 之前，下同。）

- [ ] **Step 3: P3 方案一句话（#s3）**

```html
<div style="font-size:22px;margin-bottom:30px">业务人员在 Quick Desktop / Claude Code 里把工具做完，说一句<b>“部署”</b>：</div>
<div class="mono" style="font-size:19px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:22px 26px;line-height:2.1">
  业务人员描述需求 → Agent 生成代码（合同约束）→ 说“部署”<br>
  → 流水线全自动执行（~90 秒）→ <b>https://app-xxx.your-domain.com</b><br>
  → 同事打开 URL，飞书扫码即用（权限按名单）
</div>
<div class="cols2" style="grid-template-columns:1fr 1fr 1fr;margin-top:30px">
  <div class="card" style="text-align:center"><div class="num">~90s</div><p>说“部署”到 URL 可用（实测）</p></div>
  <div class="card" style="text-align:center"><div class="num">0 次</div><p>接触 AWS 控制台</p></div>
  <div class="card" style="text-align:center"><div class="num">飞书</div><p>访问与管理权限绑定企业账号</p></div>
</div>
<div class="takeaway">这一页就是完整的用户体验——剩下 17 页解释它为什么安全、可靠、便宜。</div>
```

- [ ] **Step 4: 验证 + Commit**

Run: `python3 docs/presentation/check_slides.py` → PASS；`open docs/presentation/slides.html` 目检 P1-P3。

```bash
git add docs/presentation/slides.html
git commit -m "feat(deck): opening slides P1-P3 (cover, pain points, one-line solution)"
```

---

### Task 4: 架构逐层页（P5-P9）

**Files:**
- Modify: `docs/presentation/slides.html`（填充 `#s5`-`#s9`）

**Interfaces:**
- Consumes: `archDiagram` 的 `data-arch` 接口（P5 用 `data-arch="1"`—— ①② 两层同讲时高亮 ①，讲述中口头带 ②；P6=3、P7=4、P8=5）

P5-P8 统一版式：左侧窄栏放压暗五层图（当前层高亮）做“地图”，右侧放要点。

- [ ] **Step 1: P5 Skill+MCP（#s5）**

```html
<div class="cols2" style="grid-template-columns:0.8fr 1.2fr">
  <div class="arch" data-arch="1"></div>
  <div>
    <div class="card" style="margin-bottom:16px"><h3>部署合同是锚点</h3>
      <p><code>site.json</code> + 目录约定 + 代码红线。<b>哪个 Agent 生成的代码都行</b>，执行器只认合同；校验器把不合规产物在部署前拦下。</p></div>
    <div class="card"><h3>部署 MCP：薄壳，5 个工具</h3>
      <p><code>deploy_site / confirm_upload / get_deploy_status / list_my_sites / undeploy_site</code>——全部秒级返回，重活儿交给异步执行器。OAuth 自动携带飞书身份，谁部署的站点归谁管。</p></div>
  </div>
</div>
<div class="takeaway">合同把“生成”与“部署”解耦：Agent 随便换，平台不用动。</div>
```

- [ ] **Step 2: P6 执行器（#s6）**

```html
<div class="cols2" style="grid-template-columns:0.8fr 1.2fr">
  <div class="arch" data-arch="3"></div>
  <div>
    <div class="mono" style="background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 22px;font-size:17px;line-height:2">
      validate（合同校验/红线扫描/zip bomb 防护）<br>
      → provision-db（DynamoDB 表 / DSQL schema+role）<br>
      → CodeBuild 装依赖（--ignore-scripts）<br>
      → 站点 Lambda（zip + Web Adapter Layer）<br>
      → 前端上 S3（版本化前缀）<br>
      → 路由<b>原子切流</b> → 冒烟验证
    </div>
    <p style="margin-top:16px;font-size:18px" class="muted">Step Functions 编排，全程无人值守；任何一步失败即止损，不会出现半部署状态。重部署走同一条流水线，切流原子完成、服务不中断。</p>
  </div>
</div>
<div class="takeaway">校验前置 + 原子切流：坏产物进不来，好产物一步到位。</div>
```

- [ ] **Step 3: P7 路由鉴权（#s7）**

```html
<div class="cols2" style="grid-template-columns:0.8fr 1.2fr">
  <div class="arch" data-arch="4"></div>
  <div>
    <div class="mono" style="background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 22px;font-size:17px;line-height:2">
      请求 app-xxx.your-domain.com<br>
      → Lambda@Edge 查路由表<br>
      → 验会话 JWT（未登录 302 去登录）<br>
      → 按 allowed_users 放行<br>
      → 注入 <b>x-user-email</b> / x-user-name<br>
      → /api/* → 站点 Lambda（SigV4）；其余 → S3
    </div>
    <p style="margin-top:16px;font-size:18px" class="muted"><b style="color:var(--text)">站点代码零 auth 逻辑</b>：身份由边缘注入，站点直接读 header 即可“知道来者是谁”。业务人员不写鉴权，也写不坏鉴权。</p>
  </div>
</div>
<div class="takeaway">鉴权在边缘统一执行——站点想绕都绕不过。</div>
```

- [ ] **Step 4: P8 身份层（#s8）**

```html
<div class="cols2" style="grid-template-columns:0.8fr 1.2fr">
  <div class="arch" data-arch="5"></div>
  <div>
    <div class="card" style="margin-bottom:16px"><h3>Cognito 联邦到飞书</h3>
      <p>员工零注册：访问站点 → 飞书扫码 → 进来就带企业邮箱身份。身份源可替换为任意能给 email claim 的标准 IdP（Okta / Azure AD…），平台代码不用改。</p></div>
    <div class="card"><h3>一套身份，三处消费</h3>
      <p>① 站点访问（边缘验会话）② MCP 部署权限（OAuth token）③ Quick SSO。<b>身份即邮箱</b>——owner / 名单 / 会话 claim 全以 email 为键，对 IdP 无感。</p></div>
  </div>
</div>
<div class="takeaway">权限模型只有一个词：企业邮箱。名单写谁，谁能访问。</div>
```

- [ ] **Step 5: P9 三档 tier（#s9）**

```html
<table style="margin-bottom:24px">
  <tr><th style="width:22%">Tier</th><th>技术栈</th><th>适用场景</th></tr>
  <tr><td><b>static</b></td><td>纯前端，S3 托管</td><td>展示页、报表、计算器类小工具</td></tr>
  <tr><td><b>fullstack-nosql</b></td><td>Express + DynamoDB</td><td>记录/审批/打卡类，键值数据模型</td></tr>
  <tr><td><b>fullstack-sql</b></td><td>Express + Aurora DSQL（PostgreSQL 兼容）</td><td>需要关联查询/事务的业务工具</td></tr>
</table>
<div class="card"><h3>为什么 SQL 档选 Aurora DSQL</h3>
  <p>免 VPC（Lambda 直连）· 闲置零成本（按请求计费，贴合内部工具“偶尔用”的形态）· IAM 认证免密码管理 · PG 线协议——AI 生成的标准 PostgreSQL 代码直接能跑。</p></div>
<div class="takeaway">Agent 按需求选档；三档共用同一套部署、路由与鉴权。</div>
```

- [ ] **Step 6: 验证 + Commit**

Run: `python3 docs/presentation/check_slides.py` → PASS；`open docs/presentation/slides.html#5`，翻到 P8 确认每页地图高亮层正确（P5→①、P6→③、P7→④、P8→⑤）。

```bash
git add docs/presentation/slides.html
git commit -m "feat(deck): architecture deep-dive slides P5-P9"
```

---

### Task 5: 安全专页（P10-P11）

**Files:**
- Modify: `docs/presentation/slides.html`（填充 `#s10 #s11`）

- [ ] **Step 1: P10 安全模型（#s10）**

```html
<div style="font-size:20px;margin-bottom:22px">前提：站点代码由 Agent 生成、业务人员部署——平台<b>按不可信代码对待每一个站点</b>：</div>
<div class="cols2">
  <div class="card"><h3>算力边界</h3><p>每站点独立 IAM 角色 + <b>PermissionsBoundary</b> 封顶：站点再怎么写代码，权限天花板固定，碰不到别人的资源。</p></div>
  <div class="card"><h3>数据边界</h3><p>DSQL per-site schema + 非 admin PG role；DynamoDB 表按 <code>site-data-{site_id}-</code> 前缀隔离——跨站点读写在权限层就不成立。</p></div>
  <div class="card"><h3>供应链边界</h3><p>CodeBuild 装依赖带 <code>--ignore-scripts</code>：npm 包的安装脚本不执行，恶意包拿不到构建环境。</p></div>
  <div class="card"><h3>入口把关</h3><p>红线扫描器在部署前静态拦截危险模式（越权 SDK 调用、读环境凭证等），多轮对抗加固过。</p></div>
</div>
<div class="takeaway">安全不靠“相信生成的代码没问题”，靠边界让问题代码无事可做。</div>
```

- [ ] **Step 2: P11 鉴权正确性（#s11）**

```html
<div class="cols2" style="grid-template-columns:1fr 1fr 1fr">
  <div class="card"><h3>为什么鉴权在边缘</h3><p>放站点里：每个 Agent 生成一遍，写错一次就漏一站。放边缘：一处实现、处处生效，站点零 auth 代码。</p></div>
  <div class="card"><h3>为什么全站禁缓存</h3><p>鉴权跑在 origin-request——它<b>只在 cache miss 时执行</b>。若允许缓存，命中缓存 = 绕过鉴权。禁缓存是正确性前提，不是性能疏忽；内部工具流量下成本可忽略。</p></div>
  <div class="card"><h3>会话验签双端同步</h3><p>Edge 验签与登录服务签发使用同一 HS256 实现，<b>字节级同步</b>维护（代码注释互相锚定）；密钥存 SSM，部署时注入。</p></div>
</div>
<div class="takeaway">这三个决定都有“为什么”——欢迎在 Q&A 里挑战任何一条。</div>
```

- [ ] **Step 3: 验证 + Commit**

Run: `python3 docs/presentation/check_slides.py` → PASS；目检 P10-P11。

```bash
git add docs/presentation/slides.html
git commit -m "feat(deck): security model slides P10-P11"
```

---

### Task 6: AWS 组件全景 + 部署要求（P12、P15）

**Files:**
- Modify: `docs/presentation/slides.html`（填充 `#s12 #s15`）

- [ ] **Step 1: P12 AWS 组件全景（#s12）**

```html
<table style="font-size:16px">
  <tr><th style="width:26%">服务</th><th>在方案中的角色</th></tr>
  <tr><td><b>CloudFront</b></td><td>泛域名统一入口 <code>*.your-domain.com</code>；全站禁缓存（鉴权正确性前提）</td></tr>
  <tr><td><b>Lambda@Edge</b></td><td>路由查表 + 会话验签 + 身份注入 + 分流（每请求执行）</td></tr>
  <tr><td><b>Lambda</b></td><td>站点后端（zip + Web Adapter Layer）与登录服务</td></tr>
  <tr><td><b>S3</b></td><td>前端静态托管（版本化前缀，原子切流）</td></tr>
  <tr><td><b>DynamoDB</b></td><td>路由表 + nosql 档站点数据（按站点前缀隔离）</td></tr>
  <tr><td><b>Aurora DSQL</b></td><td>sql 档站点库：per-site schema，按请求计费、闲置零成本</td></tr>
  <tr><td><b>Step Functions</b></td><td>部署流水线编排（校验→建库→构建→部署→切流→冒烟）</td></tr>
  <tr><td><b>CodeBuild</b></td><td>依赖安装与打包（--ignore-scripts）</td></tr>
  <tr><td><b>Cognito</b></td><td>企业身份：联邦飞书 / 任意标准 IdP，签发部署与访问凭证</td></tr>
  <tr><td><b>Bedrock AgentCore</b></td><td>部署 MCP 的托管运行时（消费型计费）</td></tr>
  <tr><td><b>SSM / ACM / Route53</b></td><td>密钥与配置 / 通配符证书 / DNS</td></tr>
</table>
<div class="takeaway">全 serverless / 托管服务——没有一台需要打补丁的机器，闲置成本趋零。</div>
```

- [ ] **Step 2: P15 部署要求（#s15）**

```html
<div class="cols2">
  <div class="card"><h3>账号前置（一次性）</h3><p>
    · us-east-1 区域（Lambda@Edge / ACM 约束）<br>
    · 一个可改 DNS 的域名 + <code>*.your-domain.com</code> ACM 通配符证书<br>
    · 飞书企业自建应用（用户邮箱权限）<br>
    · 部署机装 Docker（构建用）</p></div>
  <div class="card"><h3>七阶段部署（照手册执行）</h3><p class="mono" style="font-size:16px">
    ①身份层(SSO) → ②路由层 → ③DSQL<br>→ ④执行器 → ⑤部署MCP → ⑥客户端接入<br>→ ⑦端到端彩排（E2E 全绿即验收）</p></div>
</div>
<p style="margin-top:22px;font-size:19px" class="muted">部署手册含每一步命令与全部实测坑位；<b style="color:var(--text)">换账号重部署已实测走通</b>——所有环境相关值走配置文件，代码零硬编码。</p>
<div class="takeaway">交付物是手册 + 代码库：你的团队可独立部署、独立运维，不依赖我们在场。</div>
```

- [ ] **Step 3: 验证 + Commit**

Run: `python3 docs/presentation/check_slides.py` → PASS；目检 P12/P15 表格不溢出。

```bash
git add docs/presentation/slides.html
git commit -m "feat(deck): AWS components panorama P12 and deployment prereqs P15"
```

---

### Task 7: 成本两页（P13-P14，含柱状图）

**Files:**
- Modify: `docs/presentation/slides.html`（填充 `#s13 #s14`）

**Interfaces:**
- Consumes: spec「成本模型」节的全部数字（不得改动数值）

- [ ] **Step 1: 先调用 dataviz skill**

`Skill(dataviz)` 并读其 palette 参考，确认深色主题下柱状图用色与标注规范。若其 palette 与 Task 1 的 `--accent` 冲突，回改 `:root` 变量值（类名/结构不动）。

- [ ] **Step 2: P13 假设与 free tier（#s13）**

```html
<div class="cols2" style="grid-template-columns:0.9fr 1.1fr">
  <div>
    <h3 style="font-size:20px;margin-bottom:12px">流量画像（可按你的实际校准）</h3>
    <p class="muted" style="font-size:17px;line-height:1.9">
      · 每 App 日均 100 次访问 × 10 请求，30% 打后端 API<br>
      · 30% 的 App 用 SQL 档；~5 DPU/查询（估）<br>
      · 每 App 月重部署 4 次<br>
      · 全公司几百 MAU（内部工具）</p>
  </div>
  <div>
    <h3 style="font-size:20px;margin-bottom:12px">永久免费额度（always-free / 月）</h3>
    <table style="font-size:15px">
      <tr><th>服务</th><th>免费额度</th><th>覆盖情况</th></tr>
      <tr><td>CloudFront</td><td>1TB 流出 + 1000 万请求</td><td class="ok">✅ 200 App 仍全免</td></tr>
      <tr><td>Lambda</td><td>100 万请求 + 40 万 GB-s</td><td class="ok">✅ 20/50 全免，200 略超</td></tr>
      <tr><td>Aurora DSQL</td><td>10 万 DPU + 1GB</td><td>20 App 大部分覆盖</td></tr>
      <tr><td>Step Functions</td><td>4000 次状态转换</td><td class="ok">✅ 20 App 全免</td></tr>
      <tr><td>CodeBuild</td><td>100 分钟</td><td>部分覆盖</td></tr>
      <tr><td>Cognito</td><td>10,000 MAU</td><td class="ok">✅ 三档全免</td></tr>
      <tr><td>DynamoDB</td><td>25GB 存储</td><td>存储全免，请求按量</td></tr>
    </table>
  </div>
</div>
<div class="takeaway">Lambda@Edge 是唯一无免费额度、随流量线性的项——这正是下一页数字的主要构成。</div>
```

- [ ] **Step 3: P14 测算表 + 柱状图（#s14）**

```html
<div class="cols2" style="grid-template-columns:1.15fr 0.85fr">
  <table style="font-size:14.5px">
    <tr><th>成本项</th><th>20 App</th><th>50 App</th><th>200 App</th></tr>
    <tr><td>Lambda@Edge（鉴权）</td><td>$0.5</td><td>$1.2</td><td>$4.7</td></tr>
    <tr><td>Aurora DSQL</td><td>$0.3</td><td>$1.9</td><td>$10.0</td></tr>
    <tr><td>CodeBuild</td><td>$0.7</td><td>$2.5</td><td>$11.5</td></tr>
    <tr><td>DynamoDB</td><td>$0.2</td><td>$0.4</td><td>$1.5</td></tr>
    <tr><td>CloudWatch Logs</td><td>$0.4</td><td>$1.0</td><td>$3.9</td></tr>
    <tr><td>AgentCore + SFN + S3 + Route53</td><td>$0.9</td><td>$1.5</td><td>$4.9</td></tr>
    <tr><td>CloudFront / 站点 Lambda / Cognito</td><td colspan="2" style="text-align:center">$0（free tier 内）</td><td>$0.2</td></tr>
    <tr><th>理论合计</th><th>~$3</th><th>~$8.5</th><th>~$37</th></tr>
    <tr><th>建议预算区间</th><th>$3-8</th><th>$9-18</th><th>$37-70</th></tr>
  </table>
  <div>
    <svg viewBox="0 0 380 300" width="100%">
      <text x="10" y="20" font-size="14" fill="var(--muted)">月成本（理论值，竖线=预算上界）</text>
      <line x1="50" y1="260" x2="370" y2="260" stroke="var(--line)"/>
      <!-- y 轴刻度：$70 → 220px 高度线性映射，base y=260 -->
      <g font-size="12" fill="var(--muted)" text-anchor="end">
        <text x="44" y="264">0</text><text x="44" y="139">$35</text><text x="44" y="44">$70</text>
      </g>
      <line x1="50" y1="135" x2="370" y2="135" stroke="var(--line)" stroke-dasharray="3 4"/>
      <line x1="50" y1="40" x2="370" y2="40" stroke="var(--line)" stroke-dasharray="3 4"/>
      <!-- bars: value*220/70 px; 20:$3→9px, 50:$8.5→27px, 200:$37→116px -->
      <g fill="var(--accent)">
        <rect x="80" y="251" width="56" height="9" rx="2"/>
        <rect x="180" y="233" width="56" height="27" rx="2"/>
        <rect x="280" y="144" width="56" height="116" rx="2"/>
      </g>
      <!-- range whiskers to upper bound: $8→25px, $18→57px, $70→220px -->
      <g stroke="var(--muted)" stroke-width="1.5">
        <line x1="108" y1="251" x2="108" y2="235"/><line x1="100" y1="235" x2="116" y2="235"/>
        <line x1="208" y1="233" x2="208" y2="203"/><line x1="200" y1="203" x2="216" y2="203"/>
        <line x1="308" y1="144" x2="308" y2="40"/><line x1="300" y1="40" x2="316" y2="40"/>
      </g>
      <g font-size="14" fill="var(--text)" text-anchor="middle" font-weight="600">
        <text x="108" y="228">$3</text><text x="208" y="196">$8.5</text><text x="308" y="132">$37</text>
      </g>
      <g font-size="13" fill="var(--muted)" text-anchor="middle">
        <text x="108" y="282">20 App</text><text x="208" y="282">50 App</text><text x="308" y="282">200 App</text>
      </g>
    </svg>
    <div class="card" style="margin-top:10px"><p style="font-size:16px">
      对照：传统模式每 App 一套 ALB + 最小实例 ≈ <b>$28/月</b> → 200 App 超 <b>$5,600/月</b>。本方案差两个数量级。</p></div>
  </div>
</div>
<div class="takeaway">Free tier 吃掉小规模的大头（20 App ≈ 一杯咖啡）；200 App 也不到 $70/月。<span class="muted" style="font-size:14px">（us-east-1 2026-07 Price List API 现价；PoC 实测账单 $15-50/月含开发期反复部署，可作现实锚点）</span></div>
```

- [ ] **Step 4: 数字核对**

逐格比对 spec「测算结果」表与 P14 表格（脚本精算值：20 App 各项 0.5/0.3/0.7/0.2/0.4/0.9、合计 ~$3；50 App 1.2/1.9/2.5/0.4/1.0/1.5、~$8.5；200 App 4.7/10.0/11.5/1.5/3.9/4.9/0.2、~$37）。任何不一致改 HTML 不改 spec。

- [ ] **Step 5: 验证 + Commit**

Run: `python3 docs/presentation/check_slides.py` → PASS；`open docs/presentation/slides.html#13` 目检两页、柱高与数值一致。

```bash
git add docs/presentation/slides.html
git commit -m "feat(deck): cost model slides P13-P14 with verified pricing and bar chart"
```

---

### Task 8: Manus 对比两页（P16-P17）

**Files:**
- Modify: `docs/presentation/slides.html`（填充 `#s16 #s17`）

约束回顾：**不提 Meta 收购**；基调=借鉴 Manus 的流畅体验、解耦 Agent；不贬低 Manus。

- [ ] **Step 1: P16 部署体验对比（#s16）**

```html
<div style="font-size:19px;margin-bottom:16px">Manus 证明了“对话中一句话上线”是最好的建站体验——我们把这个体验搬进企业：</div>
<table style="font-size:15.5px">
  <tr><th style="width:16%">步骤</th><th style="width:40%">Manus</th><th>本方案</th></tr>
  <tr><td>描述需求</td><td>对话框输入 prompt</td><td>Quick Desktop / Claude Code 对话（员工日常工具）</td></tr>
  <tr><td>生成代码</td><td>Manus 云 VM 生成</td><td><b>任意 Agent</b> 生成（合同约束产物格式）</td></tr>
  <tr><td>触发部署</td><td>说 “publish”</td><td>说“部署”（MCP 调用，OAuth 自动带飞书身份）</td></tr>
  <tr><td>部署过程</td><td>平台内置托管，分钟级</td><td>流水线全自动，<b>实测 ~90 秒</b>，可随时查进度</td></tr>
  <tr><td>拿到 URL</td><td>xxx.manus.space</td><td>app-xxx.<b>你的域名</b>（企业品牌）</td></tr>
  <tr><td>配访问权限</td><td>面板配内置账号/角色</td><td>site.json 写飞书邮箱名单，访问者<b>免注册</b>扫码即用</td></tr>
  <tr><td>后续迭代</td><td>对话说改动，自动重部署</td><td>同样对话式重部署，原子切流不中断</td></tr>
</table>
<div class="takeaway">体验对齐 Manus（对话→URL 一步到位）；三个关键不同——跑在你的 AWS、用你的企业身份、不绑定任何一家 Agent。</div>
```

- [ ] **Step 2: P17 架构取舍对比（#s17）**

```html
<table style="font-size:16px">
  <tr><th style="width:20%">维度</th><th>Manus（一体化）</th><th>本方案（解耦）</th></tr>
  <tr><td>Agent 与部署</td><td>生成 + 托管绑定在一个平台</td><td>部署合同做接口：任意 Skill+MCP 客户端接入</td></tr>
  <tr><td>换 Agent 代价</td><td>迁移整个应用</td><td><b>零</b>——合同不变，Agent 随便换/升级</td></tr>
  <tr><td>代码/数据归属</td><td>Manus 云（代码可导出）</td><td>客户 AWS 账号，<b>数据不出域</b></td></tr>
  <tr><td>访问身份</td><td>平台内置注册登录</td><td>企业 IdP 联邦（飞书 SSO），员工零注册</td></tr>
  <tr><td>安全边界</td><td>平台黑盒</td><td>per-site IAM boundary / schema 隔离，可审计</td></tr>
  <tr><td>成本</td><td>订阅 + credits，按任务消耗难预测</td><td>AWS 按量，200 App ~$40-70/月，可预测</td></tr>
</table>
<div class="takeaway">Manus 验证了体验标准；本方案把同样的体验实现在企业自己的云上，并把“生成”与“部署”解耦——生成能力随 Agent 生态进步，部署基础设施保持稳定。</div>
```

- [ ] **Step 3: 验证 + Commit**

Run: `python3 docs/presentation/check_slides.py` → PASS；确认两页无 “Meta” 字样：`grep -c Meta docs/presentation/slides.html` 应为 0。

```bash
git add docs/presentation/slides.html
git commit -m "feat(deck): Manus comparison slides P16-P17 (UX parity, decoupled agent)"
```

---

### Task 9: 路线图、总结、附录（P18-P20）

**Files:**
- Modify: `docs/presentation/slides.html`（填充 `#s18 #s19 #s20`）

- [ ] **Step 1: P18 二期路线图（#s18）**

```html
<div class="cols2">
  <div class="card"><h3>管理面板（Web UI）</h3><p>站点列表 / 详情 / 部署历史 / 下线操作——owner 与管理员两种视图。</p></div>
  <div class="card"><h3>在线改权限</h3><p>改 allowed_users / require_login <b>不再需要重部署</b>；MCP 工具与面板共用同一后端。</p></div>
  <div class="card"><h3>协作者与管理员</h3><p>多人共管站点、所有权转移；管理员全局视图与代管。</p></div>
  <div class="card"><h3>MCP API Key</h3><p>不支持 OAuth 的客户端免代理直连。</p></div>
  <div class="card" style="grid-column:1/-1"><h3>访问统计与审计</h3><p>每站点 PV 按天/周/月聚合；鉴权站点自带身份 → <b>真 UV 与“谁在何时访问过”的审计</b>——权限模型的自然延伸，一般网站分析做不到。</p></div>
</div>
<div class="takeaway">一期已闭环“部署+鉴权”；二期把“管理”做全。</div>
```

- [ ] **Step 2: P19 总结（#s19）**

```html
<div class="cols2" style="grid-template-columns:1fr 1fr 1fr;margin-top:20px">
  <div class="card" style="text-align:center"><div class="num">你的 AWS</div><p>代码、数据、账单全在你的账号；数据不出域，交付含手册可自运维。</p></div>
  <div class="card" style="text-align:center"><div class="num">企业身份</div><p>飞书/标准 IdP 接管访问：员工零注册，权限即邮箱名单。</p></div>
  <div class="card" style="text-align:center"><div class="num">Agent 中立</div><p>部署合同做接口，生成侧随 Agent 生态演进，平台稳定不动。</p></div>
</div>
<div style="margin-top:44px;text-align:center;font-size:20px" class="muted">Q&A · 联系方式（演讲者现场补充）</div>
<div class="takeaway">让 Agent 的产出真正走完最后一站——从“代码”到“同事在用的应用”。</div>
```

- [ ] **Step 3: P20 附录（#s20）**

```html
<div class="cols2">
  <div class="card"><h3>测试与质量</h3><p>
    · 154 个单元测试全绿（contract 67 / auth 11 / router 23 / deployer 30 / mcp 23）<br>
    · 4 个 E2E fixture 真机通过（377s）<br>
    · 真实用户站点经 OAuth 接入端到端部署成功，鉴权四态实测</p></div>
  <div class="card"><h3>交付文档</h3><p>
    · 部署手册（七阶段 + 全部实测坑位）<br>
    · 客户端接入指引（人 / Agent 两条通道）<br>
    · 部署合同参考（给站点生成方）<br>
    · 三档黄金样例站点（兼演示素材）</p></div>
</div>
<p style="margin-top:24px;font-size:16px" class="muted">备查页——现场不讲，供 Q&A 引用。</p>
<div class="takeaway">所有数字可复验：测试可重跑，部署可照手册复现。</div>
```

- [ ] **Step 4: 验证 + Commit**

Run: `python3 docs/presentation/check_slides.py` → PASS；目检 P18-P20。

```bash
git add docs/presentation/slides.html
git commit -m "feat(deck): roadmap, summary and appendix slides P18-P20"
```

---

### Task 10: 打印样式 + 全片终验

**Files:**
- Modify: `docs/presentation/slides.html`（`</style>` 前追加打印 CSS）

- [ ] **Step 1: 追加打印样式**

```css
@media print{
  @page{size:A4 landscape;margin:0}
  html,body{overflow:visible;background:var(--bg)}
  #stage{position:static;display:block}
  #deck{width:1280px;height:auto;transform:none!important}
  .slide{position:relative;display:flex!important;height:720px;page-break-after:always;
    animation:none;zoom:0.82}
  #pager{display:none}
}
```

- [ ] **Step 2: 打印验证**

`open docs/presentation/slides.html` → 浏览器打印预览：20 页、每页一张、无截断（zoom 值可微调 0.78-0.85 直至无截断）。

- [ ] **Step 3: 全片终验清单**

- `python3 docs/presentation/check_slides.py` → PASS
- 断网验证：`open` 后开发者工具 Network 面板刷新，0 个网络请求
- 键盘全路径：Home→End 逐页翻完，无空页/溢出/字号过小（投影距离 3 米可读）
- `#N` 直跳 20 个页码均正确
- 对照 spec「验收标准」四条逐一确认

- [ ] **Step 4: Commit**

```bash
git add docs/presentation/slides.html
git commit -m "feat(deck): print stylesheet and final acceptance pass"
```

---

## Self-Review 记录

- **Spec 覆盖**：20 页大纲 ↔ Task 2-9 逐页有落点；成本数字全量搬入 Task 7；Manus 两表全量搬入 Task 8；HTML 技术形态（翻页/hash/缩放/打印/单文件）落在 Task 1/10；内容红线落在 check_slides.py（Task 1）+ 终验（Task 10）。无缺口。
- **占位符扫描**：全部页给出完整 HTML 文案；无 TBD/“类似 Task N”。P19 联系方式按 spec 即为“演讲者现场补充”，非占位缺口。
- **接口一致性**：`archDiagram(highlight)` / `data-arch` 在 Task 2 定义、Task 4 消费，签名一致；CSS 类名 Task 1 定义后各任务仅消费未改名。
