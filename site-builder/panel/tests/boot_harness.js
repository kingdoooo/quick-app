/* app.js 的启动序列 harness——在最小 DOM stub 里**真正执行** boot()。
 *
 * 为什么需要它：静态断言（test_frontend_contract.py）能查"代码里有没有这个
 * 东西"，但查不出"跑起来会不会崩"。本轮真机验收之后仍然漏了一个**只在
 * 升级跳转回来那一次**才出现的崩溃：boot() 里 `location.replace('#/sites')`
 * 之后 `return`，而改 hash 是**同文档导航**——浏览器不会重新执行脚本，
 * boot 再也不继续，state.me 永远是 null，紧随其后的 hashchange → render()
 * 在 state.me.is_admin 上抛 TypeError，用户看到骨架屏卡死。
 * HTTP 层的 E2E 看不到这个（每个接口都 200），静态断言也看不到。
 *
 * 建模上必须忠于两条真实浏览器语义，否则这个 harness 自己就是假绿：
 *   ① 给 location.hash 赋值 **会**派发 hashchange（不只是 location.replace）；
 *   ② history.replaceState **不会**派发 hashchange。
 * 两条都验证过：故意改回缺陷版本时本 harness 会红（见
 * test_frontend_boot.py 的三个反向验证用例）。
 *
 * 用法：node boot_harness.js <app.js 路径> <场景名>
 *   场景 first-visit  —— 首次进入（sessionStorage 空）
 *   场景 came-back    —— 从 /console-session 升级跳转回来
 *   场景 keys-*       —— API Key 页面的 features.api_key 三态（见 KEY_SCENARIOS）
 * 输出：一行 JSON（fetched / errors / hash_after / assigned / html）
 * 退出码：0 = 取到身份且无异常；3 = 否
 */
const fs = require('fs');

const APP = process.argv[2];
const SCENARIO = process.argv[3] || 'first-visit';

const fetched = [];
const errors = [];
const assigned = [];
const hashListeners = [];
/* 每一次 innerHTML 赋值都记下来。
 * 为什么需要：Key 页面的"三态"里有两态的判据是**渲染出了什么**
 * （关闸时创建按钮不能是 disabled、admin 必须看到开关），而 fetched 只能证明
 * "发过请求"。DOM stub 每次 querySelector 都返回**新的** Proxy，所以事后从
 * 元素上读不回来，只能在赋值那一刻录。 */
const htmlWrites = [];

function stubEl() {
  return new Proxy({}, {
    get(t, k) {
      if (k === 'addEventListener' || k === 'removeEventListener') return () => {};
      if (k === 'classList') {
        return { toggle() {}, contains() { return false; }, add() {}, remove() {} };
      }
      if (k === 'dataset') return {};
      if (k === 'appendChild' || k === 'remove' || k === 'setAttribute') return () => {};
      if (k === 'getAttribute') return () => null;
      if (k === 'hasAttribute') return () => false;
      if (k === 'focus' || k === 'setSelectionRange' || k === 'click') return () => {};
      if (k === 'closest') return () => null;
      if (k === 'querySelector') return () => stubEl();
      if (k === 'querySelectorAll') return () => [];
      return t[k];
    },
    set(t, k, v) {
      if (k === 'innerHTML') htmlWrites.push(String(v));
      t[k] = v;
      return true;
    },
  });
}

const store = (m) => ({
  getItem: (k) => (m.has(k) ? m.get(k) : null),
  setItem: (k, v) => m.set(k, String(v)),
  removeItem: (k) => m.delete(k),
});

/* came-back 场景的 sessionStorage 必须是 goUpgrade() 真实写下的那两个键。
 * 写错键名会让场景退化成 first-visit，于是用例变成空转。 */
const sessionSeed = SCENARIO === 'came-back'
  ? new Map([['sb_console_return_to', '#/sites'],
             ['sb_console_upgrade_retried', '1']])
  : new Map();

/* ── Key 页面的三态场景 ──────────────────────────────────────────────
 *
 * `features.api_key` 是**两个字段**（deployed / enabled），门禁只能看 deployed。
 * 按单布尔实现时"已部署但关闸"这一格会零请求 + 空页面，管理员无处开闸——
 * 静态断言看不出这个（代码里 `enabled` 与 `deployed` 都在），必须真跑一遍。
 * is_admin 也要能单独设：开关控件只对 admin 渲染，且 GET /api/settings/api-key
 * 对非 admin 是 403，不该被请求。 */
const KEY_SCENARIOS = {
  'keys-admin-live': { admin: true, api_key: { deployed: true, enabled: true } },
  'keys-admin-gated': { admin: true, api_key: { deployed: true, enabled: false } },
  'keys-admin-undeployed': { admin: true, api_key: { deployed: false, enabled: false } },
  'keys-user-live': { admin: false, api_key: { deployed: true, enabled: true } },
  'keys-user-gated': { admin: false, api_key: { deployed: true, enabled: false } },
};
const KEYCASE = KEY_SCENARIOS[SCENARIO] || null;

/* Key 场景要直接落在 #/keys 上，且不能被"先去升级面板会话"截住——
 * 所以预置一个**新鲜的**升级标记。键名必须是 app.js 的 UPGRADE_MARK
 * （`sb_console_upgraded_at`）：写错的话 boot 会跳去 /console-session 然后
 * return，场景退化成 first-visit，全部 Key 用例静默空转。 */
const localSeed = KEYCASE
  ? new Map([['sb_console_upgraded_at', String(Date.now())]])
  : new Map();

/* 一个**含 HTML 元字符的备注名**：Key 的 name 是用户自己填的，漏一处 esc()
 * 就是控制台里的存储型 XSS（在这里执行脚本能改权限）。静态扫描按顶层 `+`
 * 切分能查大多数形态，但真跑一遍是唯一不依赖扫描器正确性的证据。 */
const HOSTILE_NAME = '<img src=x onerror=alert(1)>';
const KEY_ROWS = [
  { key_id: 'ab12cd34', name: HOSTILE_NAME, prefix: 'sk-a1b2',
    created_at: '2026-08-12T03:04:05', last_used_at: '', revoked: false },
  { key_id: 'ef56gh78', name: '旧的那把', prefix: 'sk-z9y8',
    created_at: '2026-08-01T00:00:00', last_used_at: '2026-08-11T09:00:00',
    revoked: true },
];

global.document = {
  querySelector: () => stubEl(),
  querySelectorAll: () => [],
  getElementById: () => stubEl(),
  createElement: () => stubEl(),
  addEventListener: () => {},
};
global.window = global;
global.navigator = { clipboard: null };
global.localStorage = store(localSeed);
global.sessionStorage = store(sessionSeed);
global.confirm = () => true;

const loc = {
  _hash: KEYCASE ? '#/keys' : '',
  hostname: 'console.app.example.com',
  protocol: 'https:',
  origin: 'https://console.app.example.com',
  assign(u) { assigned.push(String(u)); },
  replace(u) {
    // 同文档 fragment 导航：只改 hash（经 setter 派发 hashchange），不重新执行脚本
    if (String(u).startsWith('#')) this.hash = String(u);
    else assigned.push(String(u));
  },
};
// ① 真实语义：给 location.hash 赋值也会派发 hashchange
Object.defineProperty(loc, 'hash', {
  get() { return loc._hash; },
  set(v) {
    const next = String(v);
    if (next === loc._hash) return;
    loc._hash = next;
    for (const fn of hashListeners) {
      try { fn(); } catch (e) { errors.push(String((e && e.message) || e)); }
    }
  },
});
global.location = loc;

// ② 真实语义：replaceState 只改地址栏，**不**派发 hashchange
global.history = {
  replaceState(_state, _title, url) {
    if (String(url).startsWith('#')) loc._hash = String(url);
  },
};

global.addEventListener = (evt, fn) => {
  if (evt === 'hashchange') hashListeners.push(fn);
};

/* 按路径给不同的响应体。**Key 场景必须这样**：一份固定响应体没法同时表达
 * "/api/me 的 features 是这一格"与"/api/keys 返回哪些行"，而 features 正是被测
 * 判据本身。非 Key 场景保持原来的那份形态（既有用例依赖它）。 */
function responseFor(u) {
  if (u.includes('/api/me')) {
    return { email: 'probe@example.com', name: 'P',
             is_admin: !!(KEYCASE && KEYCASE.admin),
             features: { api_key: KEYCASE
               ? KEYCASE.api_key : { deployed: false, enabled: false } },
             sites: [], jobs: [], admins: [] };
  }
  if (u.includes('/api/settings/api-key')) {
    return KEYCASE ? KEYCASE.api_key : { deployed: false, enabled: false };
  }
  if (u.includes('/api/keys')) return { keys: KEY_ROWS };
  return { email: 'probe@example.com', name: 'P',
           is_admin: false, sites: [], jobs: [], admins: [] };
}

global.fetch = async (url) => {
  const u = String(url);
  fetched.push(u);
  return { ok: true, status: 200, json: async () => responseFor(u) };
};

process.on('unhandledRejection', (e) => {
  errors.push('unhandledRejection: ' + ((e && e.message) || e));
});

eval(fs.readFileSync(APP, 'utf8'));

/* 场景 probe：不看启动流程，只把纯判定函数的**判定表**打出来。
 * 为什么复用本 harness 而不另写一个更小的 stub：app.js 顶层就绑了
 * DOM 事件（$('#logout-btn').addEventListener…），任何"更薄"的 stub 都会在
 * 那一行崩——实测踩过。判定表用真实代码跑才有意义，所以共用这套 stub。 */
if (SCENARIO === 'probe') {
  const CASES = [
    ['首次失败·仅 ever_live', { status: 'DEPLOYING', ever_live: false }, null, true],
    ['首次失败·job 全 FAILED', { status: 'DEPLOYING', ever_live: false },
     [{ status: 'FAILED' }], true],
    ['首次部署仍在跑', { status: 'DEPLOYING', ever_live: false },
     [{ status: 'RUNNING' }], true],
    ['重部署失败·曾成功', { status: 'DEPLOYING', ever_live: true },
     [{ status: 'FAILED' }, { status: 'SUCCEEDED' }], false],
    ['正常在线', { status: 'ACTIVE', ever_live: true },
     [{ status: 'SUCCEEDED' }], false],
    ['已下线', { status: 'DELETED', ever_live: true },
     [{ status: 'DELETED' }, { status: 'SUCCEEDED' }], false],
    ['后端漏给 ever_live 但 job 成功过', { status: 'DEPLOYING' },
     [{ status: 'SUCCEEDED' }], false],
  ];
  const out = CASES.map(([desc, site, jobs, want]) => {
    const st = jobs ? deployState(site, jobs) : null;
    const badge = st ? siteStatusBadge(site, st) : listStatusBadge(site);
    return {
      desc, want, got: neverLive(site, st),
      failed: isDeployFailed(st), running: isDeployRunning(st),
      /* 文案层的实际产出：判定对了但文案说错同样是缺陷（"还在跑"被说成
       * "失败"就是本轮由这张表发现的问题）。 */
      badge_text: String(badge).replace(/<[^>]*>/g, ''),
      hint_text: st ? String(deployHint(site, st)).replace(/<[^>]*>/g, '') : '',
      callout_has_failed_wording: st
        ? /失败/.test(String(neverLiveCallout(site, st))) : false,
    };
  });
  console.log(JSON.stringify({ scenario: 'probe', cases: out }));
  process.exit(out.every((c) => c.got === c.want) ? 0 : 3);
}

setTimeout(() => {
  const askedMe = fetched.some((u) => u.includes('/api/me'));
  console.log(JSON.stringify({
    scenario: SCENARIO, fetched_me: askedMe, fetched,
    hash_after: loc._hash, assigned, errors,
    html: htmlWrites.join('\n'),
    /* 明文只应活在创建响应的那个闭包里。这两份是"有没有被存起来"的证据面
     * ——harness 里没有点击，所以创建流程不会跑，这两个断言在**本文件**只能
     * 证明启动路径没写；真正盯住明文的是 test_frontend_contract 的白名单
     * （所有 setItem 调用点逐个列举）。分工写在这里以免有人以为已经覆盖了。 */
    local_storage: Object.fromEntries(localSeed),
    session_storage: Object.fromEntries(sessionSeed),
  }));
  process.exit(askedMe && errors.length === 0 ? 0 : 3);
}, 250);
