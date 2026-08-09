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
 * 输出：一行 JSON（fetched / errors / hash_after / assigned）
 * 退出码：0 = 取到身份且无异常；3 = 否
 */
const fs = require('fs');

const APP = process.argv[2];
const SCENARIO = process.argv[3] || 'first-visit';

const fetched = [];
const errors = [];
const assigned = [];
const hashListeners = [];

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
    set(t, k, v) { t[k] = v; return true; },
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

global.document = {
  querySelector: () => stubEl(),
  querySelectorAll: () => [],
  getElementById: () => stubEl(),
  createElement: () => stubEl(),
  addEventListener: () => {},
};
global.window = global;
global.navigator = { clipboard: null };
global.localStorage = store(new Map());
global.sessionStorage = store(sessionSeed);
global.confirm = () => true;

const loc = {
  _hash: '',
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

global.fetch = async (url) => {
  fetched.push(String(url));
  return {
    ok: true,
    status: 200,
    json: async () => ({ email: 'probe@example.com', name: 'P',
                         is_admin: false, sites: [], jobs: [], admins: [] }),
  };
};

process.on('unhandledRejection', (e) => {
  errors.push('unhandledRejection: ' + ((e && e.message) || e));
});

eval(fs.readFileSync(APP, 'utf8'));

setTimeout(() => {
  const askedMe = fetched.some((u) => u.includes('/api/me'));
  console.log(JSON.stringify({
    scenario: SCENARIO, fetched_me: askedMe, fetched,
    hash_after: loc._hash, assigned, errors,
  }));
  process.exit(askedMe && errors.length === 0 ? 0 : 3);
}, 250);
