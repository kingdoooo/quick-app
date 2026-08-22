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
 *   场景 analytics-*  —— 访问统计页的三态（见 ANALYTICS_SCENARIOS）
 *   场景 sites-list*  —— 站点列表卡片与 pv7 迷你趋势（见 SITE_SCENARIOS）
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

/* ── 访问统计页的三态场景（M5 Task 9）────────────────────────────────
 *
 * 为什么必须真跑：`renderAnalyticsTab` 的成功 / 空态 / 失败三条路径在**任何
 * 地方都没有执行过**。静态断言只能证明源码里"提到了" uv_exact、"提到了"
 * catch —— 本项目栽过的正是这个形态（"30 条静态断言 + 61/61 HTTP E2E 全绿，
 * 页面仍然崩"，见本文件顶部）。
 *
 * `rows`: 'full' = 明细有数据；'none' = 明细为空（趋势仍有数据——**两张表要
 *          能各自独立为空**，一起空分不出是"哪一半的空态"写错了）。
 * `fail`: 命中该子串的请求返回非 2xx（api() 抛 ApiError），用来跑 catch 分支。 */
const A_SITE_ID = 's-probe';
const ANALYTICS_SCENARIOS = {
  'analytics-live': { rows: 'full', fail: null },
  'analytics-empty': { rows: 'none', fail: null },
  'analytics-failed': { rows: 'full', fail: '/visitors' },
};
const ACASE = ANALYTICS_SCENARIOS[SCENARIO] || null;

/* ── 站点列表的 PV 迷你趋势（M5 Task 9b）──────────────────────────────
 *
 * 为什么必须真跑：`sparkline()` 与 siteCard 里调用它那一行，在**任何地方都没
 * 有执行过**——既有场景里 `/api/sites` 返回的是空列表，走的是 emptyState()，
 * 一张卡片都不渲染。而这个函数里恰好有一条除零分支，静态断言只能查源码里有
 * 没有 `max === 0` 这个字样（M5-FINDINGS §4.8：整文件存在性检查证不了正确性，
 * 而且可能从写下那天起就是死的）。
 *
 * 夹具分工：
 *   · `s-busy` 有真实访问量 —— 证明画出来的是数据，不是一条恒定平线；
 *   · `s-quiet` 全 0 —— 走除零分支，产物里不得出现 NaN 或残缺坐标；
 *   · hostile 单开一个场景 —— 它的产物**故意**含 NaN（可执行串被数字化了），
 *     和上面混在一起会让"不得出现 NaN"那条断言没法写。 */
const S_ZERO = [0, 0, 0, 0, 0, 0, 0];
const S_BUSY = [0, 3, 12, 7, 0, 25, 9];

function siteRow(id, name, pv7) {
  return { site_id: id, name: name, status: 'ACTIVE',
           url: 'https://app-' + id + '.example.com',
           owner: 'probe@example.com', created_at: '2026-08-01T00:00:00',
           require_login: true, allowed_users: 'org', collaborators: [],
           ever_live: true, role: 'owner', pv7: pv7 };
}

/* ── pv7 的四种"不是 7 个数字"的形状 ──────────────────────────────────
 *
 * 后端读失败时给 `[]`（= 未知，`api._pv7_or_unknown`），**不是** `[0]*7`：
 * 平的 0 线与真的零访问无法区分，那是假数据。前端因此有一条"恰好 7 个有限
 * 数字"的守卫，这一组就是它的判别力证明——四种形状都必须"什么都不画"：
 *   · `[]`        —— 后端降级值（表没建 / IAM 缺 Query / 环境变量没下发）；
 *   · `[1,2,3]`   —— 长度不对。**没有守卫时它最危险**：画出一张看起来像真
 *                    数据的错图（3 个点铺满整宽），没有任何地方看得出是错的；
 *   · 字段缺失    —— 后端回滚 / 前端先上线。没有守卫时 `undefined.map` 直接
 *                    崩掉整个站点列表；
 *   · 含可执行串  —— pv7 的值域由后端契约保证是整数（`int(pv)`），所以这格
 *                    **不是**真实攻击面的建模，而是 SAFE_WRAPPERS 里
 *                    `sparkline(` 那条豁免的证明（同 toast/openModal：
 *                    被豁免者自己必须被盯住）。
 */
const S_HOSTILE = ['<img src=x onerror=alert(1)>', 0, 0, 0, 0, 0, 0];

function siteRowWithoutPv7(id, name) {
  const row = siteRow(id, name, []);
  delete row.pv7;                 // 后端根本没给这个字段
  return row;
}

const SITE_SCENARIOS = {
  'sites-list': [siteRow('s-busy', '有访问量的站', S_BUSY),
                 siteRow('s-quiet', '零访问的站', S_ZERO)],
  /* 三种都不会让"去掉守卫"的版本崩，所以这个场景能观察到**退化后的图形** */
  'sites-list-unknown': [siteRow('s-unknown', '读不到趋势的站', []),
                         siteRow('s-short', '长度不对的站', [1, 2, 3]),
                         siteRow('s-hostile', '值域被污染的站', S_HOSTILE)],
  /* 字段缺失单独一个场景：去掉守卫时它**崩整页**，混在上面会看不到那三种图形 */
  'sites-list-missing': [siteRowWithoutPv7('s-missing', '后端没给 pv7 的站')],
};
const SCASE = SITE_SCENARIOS[SCENARIO] || null;

/* Key / analytics 场景要直接落在自己的路由上，且不能被"先去升级面板会话"
 * 截住——所以预置一个**新鲜的**升级标记。键名必须是 app.js 的 UPGRADE_MARK
 * （`sb_console_upgraded_at`）：写错的话 boot 会跳去 /console-session 然后
 * return，场景退化成 first-visit，那一组用例全部静默空转。 */
const localSeed = (KEYCASE || ACASE || SCASE)
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

/* ── 访问统计的响应体（形态照 Task 8 的两个端点契约）────────────────── */

const A_SITE = {
  site_id: A_SITE_ID, name: '统计探针站', status: 'ACTIVE',
  url: 'https://app-' + A_SITE_ID + '.example.com', owner: 'probe@example.com',
  created_at: '2026-08-01T00:00:00', require_login: true, allowed_users: 'org',
  collaborators: [], ever_live: true, role: 'owner', subdomain: 'app-' + A_SITE_ID,
};
const A_JOBS = [
  { job_id: 'jjjj1111', status: 'SUCCEEDED', phase: 'smoke-test',
    created_at: '2026-08-13T10:00:00', finished_at: '2026-08-13T10:01:30',
    duration_s: 90, error: '' },
];

/* 第三个桶是 `uv_exact: false` / `uv: null`。
 *
 * **它在生产上目前打不出来**，如实说明：`analytics.py` 的 `period == "day"`
 * 分支永远给 `uv_exact=True`（只有 week/month 的桶首日早于明细窗口下界时才
 * 置 null），而本页固定请求 `period=day&n=30`。所以 `uvCell` 的标注分支是
 * **防御性**的——一旦加了周期选择器、或明细留存窗口被缩短（Task 16 会动
 * 保留期），它就会被走到。harness 造出这一格是为了证明"真会渲染成标注而不是
 * null / 0"，不是为了证明生产会走到它。 */
const A_SERIES = [
  { bucket: '2026-08-12', pv: 1234, uv: 56, pv_denied: 0, uv_exact: true },
  { bucket: '2026-08-13', pv: 7, uv: 3, pv_denied: 2, uv_exact: true },
  { bucket: '2026-08-14', pv: 9, uv: null, pv_denied: 1, uv_exact: false },
];

/* `path` 是**匿名访问者完全可控**的：任何人 curl 一个带 HTML 元字符的路径，
 * Edge 就把它原样写进 events 表（`_record_access(..., uri, ...)` 不做净化，
 * 也不该做——净化的位置在展示层），然后它渲染在**站点所有者的控制台**里。
 * 控制台是管理界面，在这里执行脚本能改权限，所以这一列的转义是真实攻击面。
 * 静态扫描按顶层 `+` 切分能查大多数形态，但真跑一遍是唯一不依赖扫描器
 * 正确性的证据（与 HOSTILE_NAME 同理）。 */
const HOSTILE_PATH = '/<img src=x onerror=alert(1)>';
const A_ROWS = [
  { ts: '2026-08-14T09:15:00', email: 'someone@example.com',
    path: '/', decision: 'allow' },
  { ts: '2026-08-14T09:16:20', email: 'outsider@example.com',
    path: '/secret', decision: 'denied_403' },
  /* email 是**空串**而不是 null：Edge 的 redirect_login 契约（302 那一刻还
   * 不知道是谁）。前端必须把它显示成"（未登录）"而不是空白格。 */
  { ts: '2026-08-14T09:17:00', email: '', path: HOSTILE_PATH,
    decision: 'redirect_login' },
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
  _hash: KEYCASE ? '#/keys'
    : ACASE ? '#/sites/' + A_SITE_ID + '/analytics'
      : SCASE ? '#/sites' : '',
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
  /* 顺序要紧：`/api/sites/s-probe/jobs` 也 includes `/api/sites/s-probe`，
   * 所以子路径必须先判，否则站点详情的响应体会被当成 jobs / 统计的响应体，
   * 页面渲染出空表而用例仍然"跑通了"。 */
  if (u.includes('/analytics')) return { period: 'day', series: A_SERIES };
  if (u.includes('/visitors')) {
    return { rows: ACASE && ACASE.rows === 'none' ? [] : A_ROWS, next: null };
  }
  if (u.includes('/jobs')) return { jobs: A_JOBS };
  /* 列表端点要**精确**匹配（结尾或带查询串），不能用 includes('/api/sites')：
   * 那会把 `/api/sites/{id}` 也吞掉，站点详情页拿到一个列表响应体，页面渲染成
   * 空壳而用例照样"跑通了"。 */
  if (SCASE && (u.endsWith('/api/sites') || u.includes('/api/sites?'))) {
    return { sites: SCASE };
  }
  if (u.includes('/api/sites/' + A_SITE_ID)) return A_SITE;
  return { email: 'probe@example.com', name: 'P',
           is_admin: false, sites: [], jobs: [], admins: [] };
}

global.fetch = async (url) => {
  const u = String(url);
  fetched.push(u);
  /* 注入失败：**非 2xx 而不是 reject**。真实的失败面是 HTTP 层
   * （403 / 500 / 502），走的是 api() 里 `if (!resp.ok) throw new ApiError`
   * 那条路——直接 reject 掉 fetch 只会测到 node 的网络错误，那不是用户会遇到
   * 的形态，也绕过了 ApiError 的 message 组装（页面显示的就是它）。 */
  /* 错误文案是一个**唯一哨兵**，不含任何用例会断言的其它字样。第一版写的是
   * "访问明细读取失败（探针注入）"，于是它把"访问明细"这个词带进了页面——
   * 而"失败态不得渲染出访问明细那张表"正是要断言的东西，那条断言就有了两个
   * 满足来源。夹具自己制造字样碰撞，与本轮记录的假绿是同一族。 */
  if (ACASE && ACASE.fail && u.includes(ACASE.fail)) {
    return { ok: false, status: 500,
             json: async () => ({ error: 'PROBE-E500-SENTINEL' }) };
  }
  return { ok: true, status: 200, json: async () => responseFor(u) };
};

process.on('unhandledRejection', (e) => {
  errors.push('unhandledRejection: ' + ((e && e.message) || e));
});

eval(fs.readFileSync(APP, 'utf8'));

/* 场景 report-error：把 reportError() 真正跑一遍，录下 toast 正文。
 *
 * 为什么必须真跑而不是静态查：reportError 对**所有** 409 追加一句
 * "（刷新后重试即可）"。对并发冲突那是对的；对坏策略数据（S1/M02 的
 * PolicyDataInvalid → 409）恰好相反——刷新一万次都不会变，而"字段缺失"那支
 * 要的动作是**部署一次**。后端把修法写进文案是 spec §4.1 接受"拒绝"这个
 * 代价的唯一前提，UI 追加一句反向指示就把它抵消掉了。
 * 静态断言只能证明源码里"提到了"那个 code，证不出追加的那句到底还在不在。
 *
 * 三格：坏数据 409 / 并发 409 / 403。第二格是**对照**——去掉整段追加逻辑
 * （而不是只对坏数据跳过）时它必须变红，否则这条修复会静默地把该重试的
 * 提示也一起删掉。 */
if (SCENARIO === 'report-error') {
  /* 默认三格用哨兵串（只关心"追加的那句在不在"，哨兵不含任何会被断言的其它
   * 字样）。**第 4 个参数**可以传一个 JSON 文件路径覆盖它——用来把后端
   * `effective_policy` **真正生成的那两段文案**灌进来，断言它们逐字渲染到
   * toast 上。那件事静态断言与哨兵串都证不了：哨兵证明"没被追加"，
   * 真文案才证明"用户读到的是那段能照着做的字"。 */
  const CASES = process.argv[4]
    ? JSON.parse(fs.readFileSync(process.argv[4], 'utf8'))
      .map((c) => [c.name, c.status, c.payload])
    : [
      ['policy-409', 409, { error: 'BAD-DATA-SENTINEL', code: 'policy_data_invalid' }],
      ['conflict-409', 409, { error: 'CONFLICT-SENTINEL' }],
      ['denied-403', 403, { error: 'DENIED-SENTINEL' }],
    ];
  /* ApiError 走**真实的 api() 那条路**造出来，不在这里 new。
   * 两个理由：① `class` 声明不会从 eval 的作用域泄漏到 global（`function`
   * 会），所以这里根本拿不到那个构造器；② 更重要的是，页面上显示的
   * `err.message` 是 api() 组装的（payload.error → super(...)），自己 new 一个
   * 就绕过了那段组装——那正是要断言的东西之一。 */
  (async () => {
    const out = [];
    for (const [name, status, payload] of CASES) {
      global.fetch = async () => ({ ok: false, status,
                                    json: async () => payload });
      htmlWrites.length = 0;
      try {
        await api('PUT', '/api/probe', {});
        out.push({ name, toast: '<api() 没有抛——夹具失效>' });
        continue;
      } catch (e) {
        reportError('保存失败', e);
      }
      out.push({ name, toast: htmlWrites.join('\n').replace(/<[^>]*>/g, '') });
    }
    console.log(JSON.stringify({ scenario: 'report-error', cases: out, errors }));
    process.exit(errors.length === 0 ? 0 : 3);
  })();
}

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
    /* 逐次写入也给出来。`html` 是**所有**写入的并集，所以"页面上没有 X"这类
     * 断言在它上面是不精确的：加载中的占位、上一次渲染的内容都还在里面。
     * 最终态要看 html_writes[-1]（统计页三态的判据全是"最后渲染出了什么"）。 */
    html_writes: htmlWrites,
    /* 明文只应活在创建响应的那个闭包里。这两份是"有没有被存起来"的证据面
     * ——harness 里没有点击，所以创建流程不会跑，这两个断言在**本文件**只能
     * 证明启动路径没写；真正盯住明文的是 test_frontend_contract 的白名单
     * （所有 setItem 调用点逐个列举）。分工写在这里以免有人以为已经覆盖了。 */
    local_storage: Object.fromEntries(localSeed),
    session_storage: Object.fromEntries(sessionSeed),
  }));
  process.exit(askedMe && errors.length === 0 ? 0 : 3);
}, 250);
