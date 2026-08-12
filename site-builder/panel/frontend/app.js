/* Site Builder Console — 视图层移植自 Open Design 原型（gitignored，不在仓库内编辑）。
 *
 * ══ 与原型的五项差异，全部是"对齐真实后端"的必要改造 ══════════════════
 *
 * ① 数据层换成真 fetch（原型是 window.API mock）。所有请求同源
 *    `/api/*`：Edge 按 route_mode=split 把它们转到 panel Function URL，
 *    其余路径走 S3 静态前缀。**不要直连 Function URL**——它是
 *    AuthType=AWS_IAM 且只授权 Edge role，直连必 403。
 *
 * ② 没有"身份切换"开关。身份是 Edge 验签后注入的 x-user-email，前端既看不到
 *    也改不了；is_admin 由后端 /api/me 给（强一致读 admins 表）。原型那个
 *    切换器是演示用的，留着会让人以为前端能提权。
 *
 * ③ 去掉 tier 徽章、PV 曲线、访问审计、API Key 的真实数据：
 *    · `tier` —— sites 表**不存这个字段**，_shape_site 也不返回（照搬会
 *      让每张卡片显示 undefined）；
 *    · PV/UV/访客明细 —— M5 才做，入口 disabled 且**不发任何请求**；
 *    · API Key —— M4 才做，同上。
 *
 * ④ PHASE_LABEL 用 jobs 表真实的**小写** phase（common.update_job 写入的值），
 *    不是 SFN 状态机节点名。SUCCEEDED 的 job 停在 `smoke-test`
 *    （mark_job.py 只改 status，不再推进 phase），所以"成功"不靠 phase 判断。
 *
 * ⑤ undeploy 是**异步**的：POST 只返回 {job_id, status: "PENDING"}，真正的
 *    删除由 site-deployer-undeploy 异步做。原型当同步处理，会让用户在"已下线"
 *    的提示后刷新看到站点仍在，以为失败。这里改成提交后轮询该站点的 job。
 *
 * ══ 面板会话（__Host-sb_console）══════════════════════════════════════
 *
 * 读接口只要站点会话；**写接口**还要面板会话（scope=console 的会话 JWT）。
 * 它由 auth 的 /console-session 签发一次性 code → console 的
 * /api/session-callback 消费 code 并 Set-Cookie。cookie 是 HttpOnly，
 * 前端**读不到**，所以这里用一个本地时间戳标记（不是凭证，只是 UI 提示）
 * 决定要不要在进入控制台时先做一次升级——判定权始终在服务端。
 *
 * 升级是整页跳转（跨域设不了 __Host- cookie，见 login_handler 的注释），
 * 所以在**用户还没开始操作时**主动做掉，避免写到一半跳走丢状态。
 */

/* ══ 常量：词表全部对齐后端真实取值 ══════════════════════════════════ */

const STATUS_LABEL = {
  ACTIVE: '运行中',
  DEPLOYING: '部署中',
  FAILED: '失败',
  DELETED: '已下线'
};
const STATUS_CLASS = {
  ACTIVE: 'badge-ok', DEPLOYING: 'badge-run', FAILED: 'badge-fail', DELETED: 'badge-off'
};
/* PURGE_FAILED：站点确实已下线，但数据清理没全部成功（undeploy.py 写入）。
 * 它**不是**"下线失败"——URL 已经打不开了，只是数据可能还在。所以标签说
 * 数据，样式取警告色而不是失败色。 */
const JOB_LABEL = {
  SUCCEEDED: '成功', FAILED: '失败', RUNNING: '进行中', PENDING: '排队中',
  DELETED: '已下线', PURGE_FAILED: '已下线·数据未清完'
};
const JOB_CLASS = {
  SUCCEEDED: 'badge-ok', FAILED: 'badge-fail', RUNNING: 'badge-run',
  PENDING: 'badge-off', DELETED: 'badge-off', PURGE_FAILED: 'badge-warn'
};

/* permissions.py 的 ROLE_* 四个常量，一个不多一个不少。
 * 原型里的 `admin_view` 不是后端取值，会让标签空白。 */
const ROLE_LABEL = {
  owner: '所有者',
  collaborator: '协作者',
  admin: '管理员代管',
  none: '无权限'
};

/* jobs 表真实 phase（deployer/functions/* 里 update_job(phase=...) 的字面量）。
 * 顺序即部署阶段顺序，进度条按它算。 */
const PHASE_LABEL = {
  'submitted': '已提交',
  'queued': '排队中',
  'validate': '校验合同',
  'provision-db': '准备数据库',
  'package': '打包依赖',
  'deploy-backend': '部署后端',
  'upload-frontend': '上传前端',
  'register-route': '注册路由',
  'smoke-test': '冒烟校验',
  'undeploy': '下线'
};
const PHASE_ORDER = ['submitted', 'queued', 'validate', 'provision-db', 'package',
                     'deploy-backend', 'upload-frontend', 'register-route', 'smoke-test'];

const ICON = {
  sites: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="2" y="2.5" width="12" height="4" rx="1"/><rect x="2" y="9.5" width="12" height="4" rx="1"/></svg>',
  key: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><circle cx="5.5" cy="10.5" r="3"/><path d="M7.7 8.3 13 3m-2 0h2v2"/></svg>',
  shield: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M8 1.8l5 1.8v4c0 3-2.1 5.4-5 6.6-2.9-1.2-5-3.6-5-6.6v-4z"/></svg>',
  search: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="7" cy="7" r="4.2"/><path d="M10.2 10.2 14 14"/></svg>',
  chevron: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M6 3.5l5 4.5-5 4.5"/></svg>',
  ok: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="8" cy="8" r="6.5"/><path d="M5 8.3l2 2 4-4.3"/></svg>',
  err: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="8" cy="8" r="6.5"/><path d="M8 5v4M8 11.2v.1"/></svg>',
  info: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="8" cy="8" r="6.5"/><path d="M8 7.4v4M8 4.9v.1"/></svg>',
  copy: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="5.5" y="5.5" width="8" height="8" rx="1.4"/><path d="M10.5 3.5H4A1.5 1.5 0 0 0 2.5 5v6.5"/></svg>',
  ext: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M9 3.5h3.5V7M12.2 3.8 7.5 8.5M12.5 10v2a1.5 1.5 0 0 1-1.5 1.5H4A1.5 1.5 0 0 1 2.5 12V5A1.5 1.5 0 0 1 4 3.5h2"/></svg>',
  empty: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3"><rect x="3" y="4" width="18" height="6" rx="1.5"/><path d="M3 14h9M3 18h6" stroke-dasharray="2 2.4"/></svg>',
  plus: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M8 3.5v9M3.5 8h9"/></svg>',
  clock: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="6.3"/><path d="M8 4.6V8l2.4 1.6"/></svg>'
};

/* ══ 小工具 ══════════════════════════════════════════════════════════ */

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

/* 控制台是**管理界面**：在这里执行脚本就能改权限。站点名 / 邮箱 / job 错误串
 * 都来自他人，一律经 esc() 才能进 innerHTML。 */
function esc(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const fmt = (n) => Number(n).toLocaleString('en-US');
const dur = (n) => (n >= 60 ? Math.floor(n / 60) + ' 分 ' + (n % 60) + ' 秒' : n + ' 秒');

function initials(email) {
  return String(email || '?').split('@')[0].split(/[.\-_]/)
    .slice(0, 2).map((p) => p[0] || '').join('').toUpperCase() || '?';
}

/* created_at 可能是空串：Task 5 的回填对"没有 job 可推导"的站点不猜时间
 * （编一个默认值会是错日期且看不出是猜的）。这里显示 — 而不是 Invalid Date。 */
function when(iso) {
  if (!iso) return '—';
  return String(iso).replace('T', ' ').slice(0, 19);
}

function statusBadge(status) {
  const cls = STATUS_CLASS[status] || 'badge-off';
  const label = STATUS_LABEL[status] || status || '未知';
  return '<span class="badge ' + cls + '"><span class="dot"></span>' + esc(label) + '</span>';
}

/* 列表里的站点徽章：DEPLOYING 且从未上线过时显示"未上线"而不是"部署中"
 * ——后者会让用户一直等一个不会来的结果（真机上有 2 个这样的站点）。 */
function listStatusBadge(item) {
  if (neverLiveFromSite(item)) {
    /* 列表页拿不到 job，**分不出"失败了"还是"还在跑"**，所以用中性文案
     * "未上线"（陈述事实：还没有可访问版本），不断言失败。点进详情页才有
     * job 数据，那里才会说清是失败还是进行中。
     * 用 badge-off（灰）而不是 badge-fail（红）：列表里一片红会让人以为出了
     * 大事，而这里只是"还没成"。 */
    return '<span class="badge badge-off"><span class="dot"></span>未上线</span>';
  }
  return statusBadge(item.status);
}

function jobBadge(status) {
  const cls = JOB_CLASS[status] || 'badge-off';
  const label = JOB_LABEL[status] || status || '未知';
  return '<span class="badge ' + cls + '"><span class="dot"></span>' + esc(label) + '</span>';
}

function phaseText(phase) {
  return PHASE_LABEL[phase] || phase || '—';
}

/* allowed_users 的两种形态：字符串 "org" 或邮箱数组。**判形态而不是判真假**
 * ——空数组是"谁都进不去"，不是"全组织"。 */
function isOrgWide(allowed) {
  return allowed === 'org' || !Array.isArray(allowed);
}

function policySummary(item) {
  if (!item.require_login) return '公开（无需登录）';
  if (isOrgWide(item.allowed_users)) return '需登录，全组织可访问';
  return '需登录，仅限 ' + item.allowed_users.length + ' 人';
}

function roleTag(role) {
  return '<span class="tag tag-role">' + esc(ROLE_LABEL[role] || role || '') + '</span>';
}

function avatarStack(emails, max) {
  const cap = max || 4;
  const list = emails || [];
  const shown = list.slice(0, cap);
  let html = '<span class="row" style="gap:0">';
  html += shown.map((e, i) => '<span class="avatar sm' + (i ? ' stackitem' : '') +
    '" title="' + esc(e) + '">' + esc(initials(e)) + '</span>').join('');
  if (list.length > cap) {
    html += '<span class="avatar sm ghost stackitem">+' + (list.length - cap) + '</span>';
  }
  if (!list.length) html += '<span class="meta">无</span>';
  return html + '</span>';
}

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/* ══ 平台域名：从 location 推导，不硬编码 ════════════════════════════
 *
 * 控制台跑在 console.{base_domain} 上，所以 base 就是 hostname 去掉首段。
 * 硬编码域名会让换环境要改前端，也容易把生产域名留在仓库里。 */
function baseDomain() {
  const parts = location.hostname.split('.');
  return parts.length > 1 ? parts.slice(1).join('.') : location.hostname;
}

function authOrigin() {
  return location.protocol + '//auth.' + baseDomain();
}

/* ══ 面板会话升级 ════════════════════════════════════════════════════ */

const UPGRADE_MARK = 'sb_console_upgraded_at';
const UPGRADE_ONCE = 'sb_console_upgrade_retried';
const UPGRADE_BACK = 'sb_console_return_to';
/* 与 console_session.CONSOLE_TTL_SECONDS 一致（4h）。标记只是 UI 提示：
 * 判定权在服务端，标记过期/错了最多多一次 401 往返，不影响正确性。 */
const UPGRADE_TTL_MS = 4 * 3600 * 1000;

function hasFreshUpgradeMark() {
  try {
    const at = Number(localStorage.getItem(UPGRADE_MARK) || 0);
    return at > 0 && (Date.now() - at) < UPGRADE_TTL_MS;
  } catch (e) {
    return false;   // 隐私模式下 localStorage 抛异常：按"没有"处理（多一次往返）
  }
}

function markUpgraded() {
  try {
    localStorage.setItem(UPGRADE_MARK, String(Date.now()));
    sessionStorage.removeItem(UPGRADE_ONCE);
  } catch (e) { /* 存不下不影响功能 */ }
}

/* 跳去 auth 换一次性 code。**整页跳转**：__Host- 前缀禁止 Domain=，
 * 跨域设不了这个 cookie，所以必须由 console 自己的 /api/session-callback 落库。
 *
 * `once` 语义：一次会话里只允许**重放一次**。升级完仍拿不到面板会话时
 * （cookie 被浏览器策略拒了、系统时钟偏移导致立刻过期）继续跳就是
 * /console-session ↔ /api/* 之间的无限跳转，用户看到白屏闪烁。 */
function goUpgrade(returnTo) {
  let retried = '';
  try {
    retried = sessionStorage.getItem(UPGRADE_ONCE) || '';
    if (!retried) {
      sessionStorage.setItem(UPGRADE_ONCE, '1');
      sessionStorage.setItem(UPGRADE_BACK, returnTo || location.hash || '#/sites');
    }
  } catch (e) { /* 存不下就退化成"不重试" */ }
  if (retried) {
    toast('面板会话无法建立', '升级后仍未获得面板会话，请重新登录后再试；' +
          '若持续如此，浏览器可能拦截了 Cookie。', 'err');
    return false;
  }
  location.assign(authOrigin() + '/console-session');
  return true;
}

/* 回到控制台后把用户送回原来的位置（升级是整页跳转，会丢 hash）。
 *
 * **用 history.replaceState 而不是 location.replace**：后者会触发 hashchange，
 * 而此刻 boot() 还没取到身份（state.me 仍是 null），hashchange → render() →
 * pageSites() 会直接在 state.me.is_admin 上抛 TypeError。replaceState 只改
 * 地址栏与历史项，**不派发 hashchange**，把渲染时机完全交回 boot()。
 * 用 replace 而非 push 是有意的：升级中转不该在后退历史里留一格
 * （用户按后退会又跳一次升级）。
 */
function restoreAfterUpgrade() {
  let back = '';
  try {
    back = sessionStorage.getItem(UPGRADE_BACK) || '';
    if (back) sessionStorage.removeItem(UPGRADE_BACK);
  } catch (e) { return false; }
  if (back && back !== location.hash) {
    try {
      history.replaceState(null, '', back);
      return true;
    } catch (e) {
      // 极老的浏览器没有 replaceState：退回改 hash。此时会触发 hashchange，
      // 但 render() 里对 state.me 有兜底（见其开头），不会抛。
      location.hash = back;
      return true;
    }
  }
  return false;
}

/* ══ 数据层：真 fetch ════════════════════════════════════════════════ */

class ApiError extends Error {
  constructor(status, payload) {
    super((payload && (payload.error || payload.need)) || ('HTTP ' + status));
    this.status = status;
    this.payload = payload || {};
  }
}

/* 写请求：credentials 必须 same-origin（否则 __Host-sb_console 不会发出，
 * 全部写请求 401），Content-Type 必须精确 application/json
 * （panel 的 check_csrf 按 media type 判定）。
 *
 * Origin **不在这里设**：浏览器会忽略脚本设的 Origin，手设它说明对 CSRF
 * 校验的理解有误——它的价值正来自"脚本无法伪造"。 */
async function api(method, path, body) {
  const init = {
    method: method,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'accept': 'application/json' }
  };
  if (body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const resp = await fetch(path, init);
  let payload = null;
  try {
    payload = await resp.json();
  } catch (e) {
    payload = null;   // 502/504 之类的非 JSON 响应
  }
  if (!resp.ok) {
    // 401 + need=console-session：读接口不会走到这里（只有写要面板会话）。
    if (resp.status === 401 && payload && payload.need === 'console-session') {
      goUpgrade(location.hash);
      throw new ApiError(401, { error: '需要面板会话，正在升级…' });
    }
    throw new ApiError(resp.status, payload);
  }
  return payload || {};
}

const apiGet = (path) => api('GET', path);

/* ══ toast / modal ═══════════════════════════════════════════════════ */

function toast(title, body, kind) {
  const type = kind || 'ok';
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.innerHTML =
    '<span class="tmark">' + (type === 'err' ? ICON.err : type === 'info' ? ICON.info : ICON.ok) + '</span>' +
    '<span><span class="ttitle">' + esc(title) + '</span>' +
    (body ? '<span class="tbody" style="display:block">' + esc(body) + '</span>' : '') + '</span>' +
    '<button class="tclose" type="button" aria-label="关闭">×</button>';
  $('#toasts').appendChild(el);
  const kill = () => el.remove();
  $('.tclose', el).addEventListener('click', kill);
  setTimeout(kill, type === 'err' ? 9000 : 4600);
}

function closeModal() { $('#modal-root').innerHTML = ''; }

function openModal(opts) {
  $('#modal-root').innerHTML =
    '<div class="scrim" data-scrim><div class="modal' + (opts.wide ? ' wide' : '') +
      '" role="dialog" aria-modal="true">' +
      '<div class="modal-head"><h2>' + esc(opts.title) + '</h2>' +
        (opts.desc ? '<p class="meta" style="margin-top:4px">' + esc(opts.desc) + '</p>' : '') + '</div>' +
      '<div class="modal-body">' + opts.body + '</div>' +
      '<div class="modal-foot">' + opts.footer + '</div>' +
    '</div></div>';
  $('[data-scrim]').addEventListener('mousedown', (ev) => {
    if (ev.target.hasAttribute('data-scrim')) closeModal();
  });
  return $('#modal-root .modal');
}

document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') closeModal(); });

/* 统一的错误提示：把后端的中文错误原样给用户（它们是写给用户看的），
 * 并对两个特殊码补充"下一步怎么办"。 */
function reportError(what, err) {
  if (err instanceof ApiError && err.status === 409) {
    toast(what, err.message + '（刷新后重试即可）', 'err');
  } else if (err instanceof ApiError && err.status === 403) {
    toast(what, err.message, 'err');
  } else {
    toast(what, (err && err.message) || '未知错误', 'err');
  }
}

/* ══ 骨架屏 ══════════════════════════════════════════════════════════ */

function skeletonTable(rows, cols) {
  let html = '<div class="card"><div class="card-body" style="display:flex;flex-direction:column;gap:16px">';
  for (let r = 0; r < (rows || 5); r++) {
    html += '<div class="row" style="gap:24px">';
    for (let c = 0; c < (cols || 5); c++) {
      html += '<div class="sk" style="flex:' + (c === 0 ? 2 : 1) + '"></div>';
    }
    html += '</div>';
  }
  return html + '</div></div>';
}

function skeletonPage() {
  return '<div class="stack" style="gap:22px"><div class="sk" style="width:200px;height:22px"></div>' +
    '<div class="sk" style="width:320px;height:13px"></div>' + skeletonTable(5, 5) + '</div>';
}

/* ══ 路由 ════════════════════════════════════════════════════════════ */

const state = {
  me: null,
  route: { page: 'sites', siteId: null, tab: 'overview' },
  siteScope: 'mine',
  listQuery: '',
  adminFilter: { q: '', status: '', owner: '' },
  draft: null,
  polling: null
};

function parseHash() {
  const raw = (location.hash || '#/sites').replace(/^#\/?/, '');
  const parts = raw.split('/').filter(Boolean);
  if (parts[0] === 'keys') return { page: 'keys' };
  if (parts[0] === 'admin') return { page: 'admin' };
  if (parts[0] === 'sites' && parts[1]) {
    return { page: 'site', siteId: parts[1], tab: parts[2] || 'overview' };
  }
  return { page: 'sites' };
}

function go(hash) { location.hash = hash; }

function stopPolling() {
  if (state.polling) { clearTimeout(state.polling); state.polling = null; }
}

/* ══ chrome ══════════════════════════════════════════════════════════ */

function renderNav() {
  const p = state.route.page;
  const item = (hash, key, label, active) =>
    '<a class="nav-item' + (active ? ' active' : '') + '" href="' + hash + '">' +
    ICON[key] + '<span>' + esc(label) + '</span></a>';

  let html = item('#/sites', 'sites', '我的站点', p === 'sites' || p === 'site');
  /* API Key（M4）：组件部署了才给真入口。
   *
   * 判据**只能是 deployed**：按 enabled 的话，管理员一关闸入口就消失，他再也
   * 找不到开关页面（见 apiKeyFeature 的注释——这是部署自锁的另一半）。
   * 未部署时保留一个**看得见的** disabled 项而不是删掉它：删掉的话用户既不
   * 知道平台有这个能力，也不知道为什么自己没有。 */
  const keyFeat = apiKeyFeature();
  if (keyFeat.deployed) {
    html += item('#/keys', 'key', 'API Key', p === 'keys');
  } else {
    html += '<span class="nav-item is-disabled coming-later" aria-disabled="true" ' +
      'title="平台尚未启用 API Key 组件">' + ICON.key +
      '<span>API Key</span><span class="tag" style="margin-left:auto">未启用</span></span>';
  }
  if (state.me && state.me.is_admin) {
    html += '<div class="nav-label">平台管理</div>';
    html += item('#/admin', 'shield', '全局管理', p === 'admin');
  }
  $('#nav-main').innerHTML = html;
  $('#user-email').textContent = state.me ? state.me.email : '';
  $('#user-avatar').textContent = state.me ? initials(state.me.email) : '';
}

function renderCrumb(items) {
  $('#breadcrumb').innerHTML = items.map((it, i) => {
    const sep = i ? '<span class="meta" style="opacity:.6">/</span>' : '';
    return sep + (it.href
      ? '<a class="meta" href="' + it.href + '" style="color:var(--muted)">' + esc(it.label) + '</a>'
      : '<span style="font-size:13px;font-weight:500">' + esc(it.label) + '</span>');
  }).join('');
}

/* ══ 页面 1：站点列表 ════════════════════════════════════════════════ */

async function pageSites() {
  const view = $('#view');
  const all = state.siteScope === 'all' && state.me.is_admin;
  renderCrumb([{ label: all ? '全部站点' : '我的站点' }]);
  view.innerHTML = skeletonPage();

  let sites;
  try {
    const res = await apiGet(all ? '/api/sites?all=1' : '/api/sites');
    sites = res.sites || [];
  } catch (err) {
    view.innerHTML = errorCard('无法加载站点列表', err);
    return;
  }

  const needle = state.listQuery.trim().toLowerCase();
  const rows = needle
    ? sites.filter((s) => (s.name + ' ' + s.site_id + ' ' + s.owner).toLowerCase().includes(needle))
    : sites;

  const scopeToggle = state.me.is_admin
    ? '<div class="segment" id="scope-switch" role="group" aria-label="站点范围">' +
        '<button type="button" data-scope="mine" aria-pressed="' + (!all) + '">我的站点</button>' +
        '<button type="button" data-scope="all" aria-pressed="' + all + '">全部站点</button>' +
      '</div>'
    : '';
  const searchBox = '<div class="search" style="width:260px"><span>' + ICON.search + '</span>' +
    '<input class="input" id="list-search" placeholder="搜索站点名 / site_id / owner" ' +
    'value="' + esc(state.listQuery) + '" /></div>';

  let html = '<section><div class="row-between" style="align-items:flex-end;margin-bottom:20px">' +
    '<div><h1>' + (all ? '全部站点' : '我的站点') + '</h1>' +
    '<p class="meta" style="margin-top:4px">' +
      (all ? '平台内全部站点，含他人拥有的站点 · 共 ' + rows.length + ' 个'
           : '我拥有或参与协作的站点 · 共 ' + rows.length + ' 个') +
    '</p></div><div class="row">' + searchBox + scopeToggle + '</div></div></section>';

  if (!rows.length && needle) {
    html += '<section class="card"><div class="empty">' +
      '<h2>没有匹配「' + esc(state.listQuery) + '」的站点</h2>' +
      '<p>试试只输入站点名的一部分，或清空搜索框。</p></div></section>';
  } else if (!rows.length) {
    html += emptyState();
  } else if (all) {
    html += siteTable(rows);
  } else {
    html += '<section class="site-grid">' + rows.map(siteCard).join('') + '</section>';
  }
  view.innerHTML = html;

  $$('#scope-switch button').forEach((b) => b.addEventListener('click', () => {
    state.siteScope = b.dataset.scope;
    state.listQuery = '';
    pageSites();
  }));
  bindSearch('#list-search', (val) => { state.listQuery = val; }, pageSites);
  $$('[data-goto]').forEach((el) => el.addEventListener('click', (ev) => {
    if (ev.target.closest('a[data-external]')) return;
    go('#/sites/' + el.dataset.goto);
  }));
}

/* 输入框防抖 + 重渲染后恢复焦点与光标位置（不然每次输入都跳走）。 */
function bindSearch(sel, setter, rerender) {
  const input = $(sel);
  if (!input) return;
  let timer;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      setter(input.value);
      rerender().then(() => {
        const again = $(sel);
        if (again) { again.focus(); again.setSelectionRange(again.value.length, again.value.length); }
      });
    }, 260);
  });
}

function siteCard(item) {
  return '<a class="site-card" href="#/sites/' + esc(item.site_id) + '">' +
    '<div class="row-between" style="align-items:flex-start">' +
      '<div style="min-width:0"><div class="name">' + esc(item.name || item.site_id) + '</div>' +
      '<span class="url" title="' + esc(item.url) + '">' +
        esc(String(item.url || '').replace(/^https:\/\//, '')) + '</span></div>' +
      listStatusBadge(item) +
    '</div>' +
    '<div class="row wrap" style="gap:6px;margin-top:12px">' +
      roleTag(item.role) +
      '<span class="tag tag-role">' + esc(policySummary(item)) + '</span>' +
    '</div>' +
    '<div class="spark-row"><div><div class="meta">创建时间</div>' +
      '<div class="mono" style="font-size:12.5px">' + esc(when(item.created_at)) + '</div></div>' +
      '<div style="text-align:right"><div class="meta">协作者</div>' +
      avatarStack(item.collaborators, 3) + '</div></div></a>';
}

function siteTable(sites) {
  return '<section class="card"><div class="card-body tight"><table class="tbl">' +
    '<thead><tr><th>站点</th><th>Owner</th><th>状态</th><th>我的角色</th>' +
    '<th>访问策略</th><th>创建时间</th><th></th></tr></thead><tbody>' +
    sites.map((item) => '<tr class="clickable" data-goto="' + esc(item.site_id) + '">' +
      '<td><div class="site-name">' + esc(item.name || item.site_id) + '</div>' +
        '<a class="mono link" data-external target="_blank" rel="noreferrer" ' +
        'href="' + esc(item.url) + '">' +
        esc(String(item.url || '').replace(/^https:\/\//, '')) + '</a></td>' +
      '<td class="mono">' + esc(item.owner) + '</td>' +
      '<td>' + listStatusBadge(item) + '</td>' +
      '<td>' + roleTag(item.role) + '</td>' +
      '<td class="meta">' + esc(policySummary(item)) + '</td>' +
      '<td class="mono">' + esc(when(item.created_at)) + '</td>' +
      '<td style="width:28px;color:var(--muted)"><span style="width:12px;display:block">' +
        ICON.chevron + '</span></td></tr>').join('') +
    '</tbody></table></div></section>';
}

function emptyState() {
  return '<section class="card"><div class="empty">' +
    '<div class="empty-mark">' + ICON.empty + '</div>' +
    '<h2>你还没有站点</h2>' +
    '<p>站点不在这里创建——在 Agent 客户端里描述你想要的页面，然后对它说「部署」，' +
    '几分钟后站点就会出现在这个列表里，并带上可分享的 URL。</p>' +
    '<div class="code-hint">对 Agent 说：把这个页面部署成内部站点</div>' +
    '<p class="meta" style="margin-top:16px">部署完成后可在此管理访问权限、协作者与下线。</p>' +
    '</div></section>';
}

function errorCard(title, err) {
  return '<div class="card"><div class="empty"><h2>' + esc(title) + '</h2>' +
    '<p>' + esc((err && err.message) || '未知错误') + '</p>' +
    '<div style="margin-top:18px"><a class="btn" href="#/sites">返回站点列表</a></div>' +
    '</div></div>';
}

/* ══ 页面 2：站点详情 ════════════════════════════════════════════════ */

async function pageSite() {
  const view = $('#view');
  const siteId = state.route.siteId;
  const tab = state.route.tab;
  renderCrumb([{ label: '我的站点', href: '#/sites' }, { label: siteId }]);
  view.innerHTML = skeletonPage();

  let site;
  try {
    site = await apiGet('/api/sites/' + encodeURIComponent(siteId));
  } catch (err) {
    /* 403 的文案与"不存在"**故意是同一句**（api.do_get_site 的注释）：
     * 能区分存在性就是站点枚举探测器。这里照样只显示后端给的话。 */
    view.innerHTML = errorCard('无法打开该站点', err);
    return;
  }

  /* 部署失败徽章由**展示层派生**：真源不会把 site.status 写成 FAILED
   * （重部署失败时站点仍在线服务旧版本，mark_job.py 只标 job）。
   *
   * 要**整份 job 列表**而不只是最新一条：区分"从未上线"与"重部署失败"必须知道
   * 历史上有没有 SUCCEEDED 过（见 deployState 的注释）。只取 [0] 分不出来。 */
  let jobs = [];
  try {
    const res = await apiGet('/api/sites/' + encodeURIComponent(siteId) + '/jobs');
    jobs = res.jobs || [];
  } catch (err) {
    jobs = [];          // 读不到部署历史不该让整页打不开
  }
  const dstate = deployState(site, jobs);
  const latestJob = dstate.latest;
  /* 从未上线的站点没有 route、URL 是 404——"打开站点"必须禁用，
   * 否则用户点进去看到 404 会以为是平台坏了。 */
  const openable = !neverLive(site, dstate);

  const tabs = [['overview', '概览'], ['access', '权限'], ['deploys', '部署历史'],
                ['analytics', '访问统计']];
  view.innerHTML =
    '<section><div class="row-between" style="align-items:flex-start;margin-bottom:18px">' +
      '<div><div class="row" style="gap:10px"><h1 class="mono" style="font-size:22px">' +
        esc(site.name || site.site_id) + '</h1>' + siteStatusBadge(site, dstate) +
        deployHint(site, dstate) + '</div>' +
        '<div class="row" style="gap:8px;margin-top:6px">' +
          (openable
            ? '<a class="mono link" target="_blank" rel="noreferrer" href="' +
              esc(site.url) + '">' + esc(site.url) + '</a>'
            : '<span class="mono meta" title="该站点从未成功上线，此 URL 目前是 404">' +
              esc(site.url) + '</span>') +
          '<span class="meta">· site_id ' + esc(site.site_id) + '</span></div></div>' +
      '<div class="row" style="gap:8px">' +
        (openable
          ? '<a class="btn" target="_blank" rel="noreferrer" href="' + esc(site.url) + '">' +
            ICON.ext + '打开站点</a>'
          : '<span class="btn is-disabled coming-later" aria-disabled="true" ' +
            'title="该站点从未成功上线，URL 目前是 404">' + ICON.ext + '打开站点</span>') +
        '<button class="btn" id="copy-url" type="button">' + ICON.copy + '复制 URL</button>' +
      '</div></div>' +
    '<div class="tabs" role="tablist">' + tabs.map((t) =>
      '<button class="tab" role="tab" data-tab="' + t[0] + '" aria-selected="' +
      (t[0] === tab) + '">' + esc(t[1]) + '</button>').join('') +
    '</div></section><div id="tabpanel"></div>' + dangerZone(site);

  $('#copy-url').addEventListener('click', () => {
    if (navigator.clipboard) navigator.clipboard.writeText(site.url);
    toast('URL 已复制', site.url, 'info');
  });
  $$('.tab').forEach((b) => b.addEventListener('click', () =>
    go('#/sites/' + siteId + '/' + b.dataset.tab)));
  bindDangerZone(site, latestJob);

  const panel = $('#tabpanel');
  if (tab === 'access') renderAccessTab(panel, site);
  else if (tab === 'deploys') renderDeploysTab(panel, site);
  else if (tab === 'analytics') renderAnalyticsTab(panel);
  else renderOverviewTab(panel, site, dstate);
}

/* `site.status === 'DEPLOYING'` 有**两种**完全不同的含义，必须区分，
 * 否则"部署中"与"部署失败"两个徽章并排出现，读起来像自相矛盾。
 *
 * 真源侧的事实（`site.status` 只有三个写入点）：
 *   · `create_site_record` 建站时写 DEPLOYING（**首次**，且这是它的初始值）
 *   · `mark_job` 成功时写 ACTIVE
 *   · `undeploy` 写 DELETED
 * **没有任何地方把它从 DEPLOYING 改回去**。所以 DEPLOYING 是"从未成功过"
 * 与"正在部署"共用的值，靠 site 自己分不出来——必须看 job 历史：
 *
 *   有 SUCCEEDED 过 → 站点**曾经上线**。此刻 DEPLOYING+FAILED = 重部署失败，
 *                     线上仍在服务旧版本（mark_job 只标 job，不回退 site）。
 *   从未 SUCCEEDED  → 站点**从未上线**（无 route、URL 404）。说"最近一次部署
 *                     失败"会让用户以为原本有个好的版本，其实一次都没成过。
 *
 * 第二种情况实测存在（真机上 27 个站点里有 2 个），我第一版对两者用了同一句
 * "最近一次部署失败"——按重部署那个假设写的，对首次失败是误导。
 */
function deployState(site, jobs) {
  const list = jobs || [];
  const latest = list[0] || null;
  const everLive = list.some((j) => j.status === 'SUCCEEDED');
  return { latest: latest, everLive: everLive, list: list };
}

/* "还没有可访问版本"的**唯一判定**（= 站点从未成功上线过）。写成一个函数而
 * 不是在多处各写一遍同样的条件：这个仓库栽过几次"同一个不变量被手抄多份，
 * 改一处漏三处"。
 *
 * 两个数据来源：
 *   · 列表页只有 site（没有 job 数据）→ 用后端给的 `ever_live`
 *     （按 last_job_id 的存在性派生，见 api._shape_site 的注释）；
 *   · 详情页另外拿到了 job 列表 → 用"历史上有没有 SUCCEEDED"交叉核对。
 *     两个来源不一致时**取更保守的那个**（认为还没上线），不给"站点在线"的
 *     乐观错觉。
 *
 * **注意它不区分"失败了"与"还在跑"**——两者都还没有可访问版本，但对用户是两
 * 件事：一个要去修，一个只需要等。所以文案层再用 isDeployFailed() 分流；
 * 判定表用例里"首次部署仍在跑"就是靠这个区分才不会被说成失败的
 * （harness 的 probe 场景把这张表打出来）。
 */
function neverLive(site, st) {
  if (site.status !== 'DEPLOYING') return false;
  const byField = site.ever_live === false;         // 后端派生（列表页唯一依据）
  const byJobs = st && st.list && st.list.length
    ? !st.everLive : null;                          // 详情页才有
  if (byJobs === null) return byField;
  return byField || byJobs;
}

/* 最新一次尝试是**失败**了（而不是还在跑）。没有 job 数据时返回 false：
 * 宁可少说一句"失败"，也不要把一个正在部署的站点说成失败的。 */
function isDeployFailed(st) {
  return !!(st && st.latest && st.latest.status === 'FAILED');
}

/* 还在部署中（首次或重部署都算）。 */
function isDeployRunning(st) {
  return !!(st && st.latest
            && (st.latest.status === 'RUNNING' || st.latest.status === 'PENDING'));
}

/* 列表页用：只有 site，没有 job。 */
function neverLiveFromSite(site) {
  return neverLive(site, null);
}

function deployHint(site, st) {
  const job = st.latest;
  if (site.status !== 'DEPLOYING' || !job) return '';
  if (job.status === 'RUNNING' || job.status === 'PENDING') {
    return '<span class="tag">' + ICON.clock + ' ' + esc(phaseText(job.phase)) + '</span>';
  }
  if (job.status === 'FAILED') {
    return st.everLive
      ? '<span class="tag" style="color:var(--danger)">最近一次部署失败（线上仍是上一版）</span>'
      : '<span class="tag" style="color:var(--danger)">从未成功上线</span>';
  }
  return '';
}

/* 状态徽章：DEPLOYING 且从未成功过时**不显示"部署中"**——它不在部署，
 * 它是停在初始状态。显示"部署中"会让用户一直等一个不会来的结果。 */
function siteStatusBadge(site, st) {
  if (neverLive(site, st) && isDeployFailed(st)) {
    return '<span class="badge badge-fail"><span class="dot"></span>未上线</span>';
  }
  return statusBadge(site.status);
}

/* 给"从未上线"的站点一句能照做的下一步。它没有 route、URL 是 404，
 * 所以"打开站点"按钮也该是禁用的（见 pageSite）。 */
function neverLiveCallout(site, st) {
  if (!(neverLive(site, st) && isDeployFailed(st))) return '';
  return '<div class="callout danger" style="margin-top:14px">' + ICON.err +
    '<span><strong>这个站点从未成功上线。</strong>首次部署在「' +
    esc(phaseText(st.latest.phase)) + '」阶段失败，因此还没有可访问的版本——' +
    '现在打开它的 URL 会是 404。<br />在 Agent 客户端里按下面的错误摘要修好后，' +
    '重新说一次「部署」即可；不需要在这里做任何操作。</span></div>';
}

function renderOverviewTab(panel, site, st) {
  const job = st.latest;
  panel.innerHTML =
    '<section style="display:grid;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);gap:16px">' +
      '<div class="card"><div class="card-head"><h2>站点信息</h2>' +
        '<span class="meta">创建于 ' + esc(when(site.created_at)) + '</span></div>' +
        '<div class="card-body"><dl class="kv">' +
          '<dt>访问地址</dt><dd>' + (neverLive(site, st)
            ? '<span class="mono meta">' + esc(site.url) +
              '</span><div class="meta" style="margin-top:4px">该地址目前返回 404</div>'
            : '<a class="mono link" target="_blank" rel="noreferrer" href="' +
              esc(site.url) + '">' + esc(site.url) + '</a>') + '</dd>' +
          '<dt>状态</dt><dd>' + siteStatusBadge(site, st) + '</dd>' +
          '<dt>子域</dt><dd class="mono">' + esc(site.subdomain || '—') + '</dd>' +
          '<dt>所有者</dt><dd><span class="row" style="gap:7px">' +
            '<span class="avatar sm">' + esc(initials(site.owner)) + '</span>' +
            '<span class="mono">' + esc(site.owner) + '</span>' +
            (site.owner === state.me.email ? '<span class="tag tag-role">我</span>' : '') +
            '</span></dd>' +
          '<dt>协作者</dt><dd>' + avatarStack(site.collaborators) +
            ((site.collaborators || []).length
              ? '<div class="meta" style="margin-top:6px">' +
                site.collaborators.map(esc).join(' · ') + '</div>' : '') + '</dd>' +
          '<dt>我的角色</dt><dd>' + roleTag(site.role) + '</dd>' +
        '</dl>' + neverLiveCallout(site, st) + '</div></div>' +
      '<div class="stack" style="gap:16px">' +
        '<div class="card"><div class="card-head"><h2>访问策略</h2>' +
          '<a class="btn btn-sm" href="#/sites/' + esc(site.site_id) + '/access">修改</a></div>' +
          '<div class="card-body"><div class="row" style="gap:9px">' +
            '<span class="badge ' + (site.require_login ? 'badge-run' : 'badge-off') +
              '"><span class="dot"></span>' + (site.require_login ? '需登录' : '公开') + '</span>' +
            '<span style="font-size:13.5px">' + esc(policySummary(site)) + '</span></div>' +
          (site.require_login && !isOrgWide(site.allowed_users)
            ? '<div class="row wrap" style="gap:6px;margin-top:12px">' +
              site.allowed_users.map((e) =>
                '<span class="etag" style="padding-right:8px">' + esc(e) + '</span>').join('') + '</div>'
            : '<p class="meta" style="margin-top:10px">' +
              (site.require_login ? '组织内任何通过 SSO 登录的人都可访问。'
                                  : '任何拿到链接的人都可访问。') + '</p>') +
        '</div></div>' +
        '<div class="card"><div class="card-head"><h2>最近一次部署</h2>' +
          '<a class="btn btn-sm" href="#/sites/' + esc(site.site_id) + '/deploys">全部记录</a></div>' +
          '<div class="card-body">' + (job
            ? '<div class="row-between"><div class="row" style="gap:9px">' + jobBadge(job.status) +
                '<span class="meta">' + esc(when(job.created_at)) + '</span></div>' +
                (job.status === 'FAILED'
                  ? '<span class="tag" style="color:var(--danger)">' +
                    esc(phaseText(job.phase)) + '</span>' : '') + '</div>' +
              '<dl class="kv" style="margin-top:14px;grid-template-columns:76px 1fr">' +
                '<dt>触发者</dt><dd class="mono">' + esc(job.by) + '</dd>' +
                '<dt>job_id</dt><dd class="mono">' + esc(job.job_id) + '</dd>' +
                (job.duration_s ? '<dt>耗时</dt><dd class="num">' + esc(dur(job.duration_s)) +
                  '</dd>' : '') + '</dl>' +
              (job.error ? '<div class="callout danger" style="margin-top:12px">' + ICON.err +
                '<span>' + esc(job.error) + '</span></div>' : '')
            : '<p class="meta">暂无部署记录。</p>') +
        '</div></div></div></section>';
}

/* ── 权限页 ─────────────────────────────────────────────────────────── */

function renderAccessTab(panel, site) {
  /* 谁能改什么，**以后端 role 为准**（permissions.CAPABILITIES）：
   *   set_access_policy: owner / collaborator / admin
   *   manage_collaborators, transfer_owner: owner / admin
   * 前端据此禁用按钮只是体验；真正的判定在服务端与写入同一次快照事务里。 */
  const role = site.role;
  const mayPolicy = role === 'owner' || role === 'collaborator' || role === 'admin';
  const mayManage = role === 'owner' || role === 'admin';

  const fresh = {
    site_id: site.site_id,
    require_login: !!site.require_login,
    mode: isOrgWide(site.allowed_users) ? 'org' : 'list',
    allowed_users: isOrgWide(site.allowed_users) ? [] : site.allowed_users.slice(),
    collaborators: (site.collaborators || []).slice()
  };
  const draft = (state.draft && state.draft.site_id === site.site_id) ? state.draft : fresh;
  state.draft = draft;

  panel.innerHTML =
    '<section style="display:grid;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);' +
      'gap:16px;align-items:start">' +
      '<div class="stack" style="gap:16px">' +
        '<div class="card"><div class="card-head"><div><h2>访问控制</h2>' +
          '<p class="meta" style="margin-top:2px">改权限不需要重新部署，保存后由边缘节点直接生效。</p>' +
          '</div>' + (mayPolicy ? '' : '<span class="tag tag-role">你无权修改</span>') + '</div>' +
          '<div class="card-body stack" style="gap:16px">' +
            '<div class="row-between" style="align-items:flex-start">' +
              '<div><div style="font-size:13.5px;font-weight:500">需要登录</div>' +
                '<p class="meta" style="max-width:44ch">关闭后任何拿到链接的人都能访问。</p></div>' +
              '<button class="switch" id="sw-login" role="switch" aria-checked="' +
                draft.require_login + '"' + (mayPolicy ? '' : ' disabled') +
                ' aria-label="需要登录"></button></div>' +
            '<div id="allow-block"' + (draft.require_login ? '' : ' class="hide"') + '>' +
              '<div class="row-between" style="margin-bottom:8px"><h3>访问名单</h3></div>' +
              '<div class="radio-card" data-mode="org" data-checked="' +
                (draft.mode === 'org') + '"><span class="radio-mark"></span><span>' +
                '<span class="radio-title">全组织可访问</span>' +
                '<span class="radio-desc" style="display:block">任何通过公司 SSO 登录的同事都可打开' +
                '（allowed_users = "org"）。</span></span></div>' +
              '<div class="radio-card" data-mode="list" data-checked="' +
                (draft.mode === 'list') + '"><span class="radio-mark"></span>' +
                '<span style="flex:1"><span class="radio-title">指定名单</span>' +
                '<span class="radio-desc" style="display:block">只有名单内的邮箱能访问，' +
                '其他人看到 403。</span></span></div>' +
              '<div id="allow-list"' + (draft.mode === 'list' ? '' : ' class="hide"') +
                ' style="margin-top:10px"></div>' +
            '</div></div>' +
          '<div class="card-foot"><span class="meta">保存后约 1 分钟内全网生效</span>' +
            '<div class="row" style="gap:8px">' +
              '<button class="btn" id="access-reset" type="button">放弃修改</button>' +
              '<button class="btn btn-primary" id="access-save" type="button"' +
                (mayPolicy ? '' : ' disabled') + '>保存访问策略</button>' +
            '</div></div></div>' +

        '<div class="card"><div class="card-head"><div><h2>协作者</h2>' +
          '<p class="meta" style="margin-top:2px">协作者可查看状态与部署历史，并可重新部署站点。</p>' +
          '</div>' + (mayManage ? '' : '<span class="tag tag-role">仅所有者可修改</span>') + '</div>' +
          '<div class="card-body stack" style="gap:12px">' +
            '<div id="collab-list"></div>' +
            '<div class="row" style="gap:8px">' +
              '<input class="input mono" id="collab-input" placeholder="name@example.com" ' +
                (mayManage ? '' : 'disabled') + ' style="flex:1" />' +
              '<button class="btn" id="collab-add" type="button" ' +
                (mayManage ? '' : 'disabled') + '>' + ICON.plus + '添加</button>' +
            '</div></div></div></div>' +

      '<div class="stack" style="gap:16px">' +
        '<div class="card"><div class="card-head"><h2>当前生效策略</h2></div><div class="card-body">' +
          '<div class="row" style="gap:9px"><span class="badge ' +
            (site.require_login ? 'badge-run' : 'badge-off') + '"><span class="dot"></span>' +
            (site.require_login ? '需登录' : '公开') + '</span>' +
            '<span style="font-size:13.5px">' + esc(policySummary(site)) + '</span></div>' +
          '<p class="meta" style="margin-top:10px">这里是服务端当前生效的值；左侧是未保存的编辑草稿。</p>' +
        '</div></div>' +
        '<div class="card"><div class="card-head"><h2>所有权转移</h2></div>' +
          '<div class="card-body stack" style="gap:12px">' +
          '<div class="callout danger">' + ICON.err +
            '<span>转移后你将降为<strong>协作者</strong>，失去协作者管理与下线权限。' +
            '此操作只能由新所有者转回。</span></div>' +
          '<dl class="kv" style="grid-template-columns:76px 1fr"><dt>当前所有者</dt>' +
            '<dd class="mono">' + esc(site.owner) + '</dd></dl>' +
          '<button class="btn btn-danger" id="transfer-btn" type="button"' +
            (mayManage ? '' : ' disabled') + '>转移所有权…</button>' +
          (mayManage ? '' : '<p class="meta">你不是该站点所有者，无法转移所有权。</p>') +
        '</div></div></div></section>';

  function renderAllowList() {
    $('#allow-list').innerHTML =
      '<div class="taginput" id="allow-tags">' +
        draft.allowed_users.map((e) => '<span class="etag">' + esc(e) +
          '<button type="button" data-rm="' + esc(e) + '" aria-label="移除 ' + esc(e) +
          '">×</button></span>').join('') +
        '<input id="allow-input" placeholder="输入邮箱后回车添加"' +
          (mayPolicy ? '' : ' disabled') + ' /></div>' +
      '<p class="meta" style="margin-top:6px">当前 ' + draft.allowed_users.length +
        ' 人 · 回车或逗号分隔添加，<span class="kbd">Backspace</span> 删除最后一个</p>';
    $$('#allow-tags [data-rm]').forEach((b) => b.addEventListener('click', () => {
      draft.allowed_users = draft.allowed_users.filter((e) => e !== b.dataset.rm);
      renderAllowList();
    }));
    const input = $('#allow-input');
    input.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ',') {
        ev.preventDefault();
        const val = input.value.trim().replace(/,$/, '');
        if (!val) return;
        if (!EMAIL_RE.test(val)) { toast('邮箱格式不正确', val, 'err'); return; }
        if (draft.allowed_users.includes(val)) {
          toast('该邮箱已在名单中', val, 'info'); input.value = ''; return;
        }
        draft.allowed_users.push(val);
        renderAllowList();
        $('#allow-input').focus();
      } else if (ev.key === 'Backspace' && !input.value && draft.allowed_users.length) {
        draft.allowed_users.pop();
        renderAllowList();
        $('#allow-input').focus();
      }
    });
  }
  renderAllowList();

  function renderCollabs() {
    const list = $('#collab-list');
    if (!draft.collaborators.length) {
      list.innerHTML = '<p class="meta">还没有协作者。所有者休假时，协作者可以代为查看与重新部署。</p>';
      return;
    }
    list.innerHTML = '<div class="taginput' + (mayManage ? '' : ' is-disabled') +
      '" style="min-height:auto">' +
      draft.collaborators.map((e) => '<span class="etag">' + esc(e) +
        (mayManage ? '<button type="button" data-rmc="' + esc(e) + '" aria-label="移除 ' +
          esc(e) + '">×</button>' : '') + '</span>').join('') + '</div>';
    $$('[data-rmc]').forEach((b) => b.addEventListener('click', async () => {
      const target = b.dataset.rmc;
      b.disabled = true;
      try {
        /* **增量语义**：后端是 add/remove 两个列表，不是整份覆盖。
         * 传整份会在并发下丢掉别人刚加的协作者（后写覆盖前写）。 */
        const res = await api('PUT', '/api/sites/' + encodeURIComponent(site.site_id) +
          '/collaborators', { remove: [target] });
        draft.collaborators = res.collaborators || [];
        renderCollabs();
        toast('已移除协作者', target, 'ok');
      } catch (err) {
        b.disabled = false;
        reportError('移除失败', err);
      }
    }));
  }
  renderCollabs();

  async function addCollab() {
    const input = $('#collab-input');
    const btn = $('#collab-add');
    const val = input.value.trim();
    if (!val) return;
    if (!EMAIL_RE.test(val)) { toast('邮箱格式不正确', val, 'err'); return; }
    if (val === site.owner) { toast('该邮箱已是站点所有者', val, 'info'); return; }
    if (draft.collaborators.includes(val)) { toast('该邮箱已是协作者', val, 'info'); return; }
    btn.disabled = true;
    try {
      const res = await api('PUT', '/api/sites/' + encodeURIComponent(site.site_id) +
        '/collaborators', { add: [val] });
      draft.collaborators = res.collaborators || [];
      input.value = '';
      renderCollabs();
      toast('已添加协作者', val, 'ok');
    } catch (err) {
      reportError('添加失败', err);
    } finally {
      btn.disabled = false;
    }
  }
  $('#collab-add').addEventListener('click', addCollab);
  $('#collab-input').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') addCollab(); });

  $('#sw-login').addEventListener('click', () => {
    if (!mayPolicy) return;
    draft.require_login = !draft.require_login;
    $('#sw-login').setAttribute('aria-checked', String(draft.require_login));
    $('#allow-block').classList.toggle('hide', !draft.require_login);
  });
  $$('.radio-card').forEach((c) => c.addEventListener('click', () => {
    if (!mayPolicy) return;
    draft.mode = c.dataset.mode;
    $$('.radio-card').forEach((x) => { x.dataset.checked = String(x.dataset.mode === draft.mode); });
    $('#allow-list').classList.toggle('hide', draft.mode !== 'list');
  }));

  $('#access-reset').addEventListener('click', () => {
    state.draft = null;
    renderAccessTab(panel, site);
    toast('已放弃未保存的修改', null, 'info');
  });

  $('#access-save').addEventListener('click', async () => {
    const btn = $('#access-save');
    /* 空名单在后端会被 normalize_allowed_users 拒（ValueError → 400），
     * 但在这里先挡一次能给出更贴的提示，也少一次白跑的往返。 */
    if (draft.require_login && draft.mode === 'list' && !draft.allowed_users.length) {
      toast('访问名单不能为空', '请添加至少一个邮箱，或改为「全组织可访问」', 'err');
      return;
    }
    btn.disabled = true;
    btn.textContent = '保存中…';
    try {
      await api('PUT', '/api/sites/' + encodeURIComponent(site.site_id) + '/permissions', {
        require_login: draft.require_login,
        allowed_users: draft.mode === 'org' ? 'org' : draft.allowed_users
      });
      state.draft = null;
      toast('访问策略已保存', '约 1 分钟内全网生效', 'ok');
      pageSite();
    } catch (err) {
      reportError('保存失败', err);
      btn.disabled = false;
      btn.textContent = '保存访问策略';
    }
  });

  $('#transfer-btn').addEventListener('click', () => {
    const candidates = (site.collaborators || []).slice();
    const modal = openModal({
      title: '转移「' + (site.name || site.site_id) + '」的所有权',
      desc: '新所有者将获得全部管理权限；你会被自动降为协作者。',
      body:
        '<div class="callout danger">' + ICON.err + '<span><strong>此操作不可自行撤销。</strong>' +
          '转移完成后，只有新所有者能把所有权转回给你。</span></div>' +
        '<div class="field"><label for="new-owner">新所有者</label>' +
          (candidates.length
            ? '<select class="input mono" id="new-owner">' + candidates.map((e) =>
                '<option value="' + esc(e) + '">' + esc(e) + '</option>').join('') + '</select>' +
              '<p class="meta">只能转给现有协作者。需要转给其他人时，请先把他加为协作者。</p>'
            : '<p class="meta">该站点还没有协作者。请先添加协作者，再转移所有权。</p>') +
        '</div>',
      footer: '<button class="btn" data-close type="button">取消</button>' +
              '<button class="btn btn-danger" id="do-transfer" type="button"' +
              (candidates.length ? '' : ' disabled') + '>确认转移</button>'
    });
    $('[data-close]', modal).addEventListener('click', closeModal);
    const sel = $('#new-owner', modal);
    const btn = $('#do-transfer', modal);
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = '转移中…';
      try {
        await api('PUT', '/api/sites/' + encodeURIComponent(site.site_id) + '/owner',
                  { new_owner: sel.value });
        closeModal();
        state.draft = null;
        toast('所有权已转移', '你现在是该站点的协作者', 'ok');
        pageSite();
      } catch (err) {
        reportError('转移失败', err);
        btn.disabled = false;
        btn.textContent = '确认转移';
      }
    });
  });
}

/* ── 部署历史 ───────────────────────────────────────────────────────── */

async function renderDeploysTab(panel, site) {
  panel.innerHTML = skeletonTable(4, 5);
  let jobs;
  try {
    const res = await apiGet('/api/sites/' + encodeURIComponent(site.site_id) + '/jobs');
    jobs = res.jobs || [];
  } catch (err) {
    panel.innerHTML = errorCard('无法加载部署历史', err);
    return;
  }

  if (!jobs.length) {
    panel.innerHTML = '<div class="card"><div class="empty"><h2>还没有部署记录</h2>' +
      '<p>在 Agent 客户端里说「部署」后，这里会出现每次部署的阶段与结果。</p></div></div>';
    return;
  }

  panel.innerHTML = '<section class="card">' +
    '<div class="card-head"><div><h2>部署历史</h2>' +
      '<p class="meta" style="margin-top:2px">共 ' + jobs.length +
      ' 次 · 失败记录可展开查看阶段与错误摘要</p></div>' +
      '<span class="meta">阶段名对应部署任务的 phase 字段</span></div>' +
    '<div class="card-body tight"><table class="tbl">' +
    '<thead><tr><th style="width:30px"></th><th>时间</th><th>触发者</th><th>结果</th>' +
    '<th>阶段</th><th class="num-col">耗时</th><th>job_id</th></tr></thead><tbody>' +
    jobs.map((job, i) => {
      const failed = job.status === 'FAILED';
      /* SUCCEEDED 的 job 的 phase 停在 smoke-test（mark_job 不再推进 phase），
       * 所以成功那行不显示阶段——显示"smoke-test"会让人以为卡在冒烟。 */
      const phaseCell = job.status === 'SUCCEEDED'
        ? '<span class="meta">全部通过</span>'
        : '<span class="tag"' + (failed ? ' style="color:var(--danger)"' : '') + '>' +
          esc(phaseText(job.phase)) + progressHint(job) + '</span>';
      return '<tr' + (failed ? ' class="clickable" data-expand="' + i + '"' : '') + '>' +
        '<td>' + (failed ? '<button class="expander" type="button" aria-expanded="false" ' +
          'data-exp-btn="' + i + '">' + ICON.chevron + '</button>' : '') + '</td>' +
        '<td class="mono">' + esc(when(job.created_at)) + '</td>' +
        '<td class="mono">' + esc(job.by) + '</td>' +
        '<td>' + jobBadge(job.status) + '</td>' +
        '<td>' + phaseCell + '</td>' +
        '<td class="num-col">' + (job.duration_s ? esc(dur(job.duration_s)) : '—') + '</td>' +
        '<td class="mono muted">' + esc(job.job_id) + '</td></tr>' +
        (failed ? '<tr class="detail-row hide" data-detail="' + i + '"><td colspan="7">' +
          '<div class="callout danger">' + ICON.err + '<span><strong>' +
          esc(phaseText(job.phase)) + ' 阶段失败</strong><br />' +
          esc(job.error || '（这次失败没有留下错误摘要）') + '</span></div>' +
          '<p class="meta" style="margin-top:8px">修好后在 Agent 客户端里重新说「部署」即可重试；' +
          '此次失败不影响线上正在运行的版本。</p></td></tr>' : '');
    }).join('') + '</tbody></table></div></section>';

  $$('[data-expand]').forEach((tr) => tr.addEventListener('click', () => {
    const i = tr.dataset.expand;
    const row = $('[data-detail="' + i + '"]');
    const btn = $('[data-exp-btn="' + i + '"]');
    const open = row.classList.contains('hide');
    row.classList.toggle('hide', !open);
    btn.setAttribute('aria-expanded', String(open));
  }));
}

/* 进行中的 job 显示"第几步/共几步"。undeploy 不在 PHASE_ORDER 里（它是另一条
 * 路径，不是部署的一个阶段），所以拿不到序号时不显示，而不是显示 0/9。 */
function progressHint(job) {
  if (job.status !== 'RUNNING' && job.status !== 'PENDING') return '';
  const idx = PHASE_ORDER.indexOf(job.phase);
  if (idx < 0) return '';
  return ' <span class="meta">' + (idx + 1) + '/' + PHASE_ORDER.length + '</span>';
}

/* ── 访问统计（M5 占位）────────────────────────────────────────────── */

function renderAnalyticsTab(panel) {
  /* **不发任何请求**：M5 的 /api/analytics、/api/visitors 都不存在，
   * 请求它们只会拿到 404（handler 对未知路由返回 404 而不是 401，
   * 见 handler.py 的 docstring）。假接口/假数据一律不写。 */
  panel.innerHTML =
    '<section class="card coming-later" aria-disabled="true"><div class="empty">' +
      '<div class="empty-mark">' + ICON.clock + '</div>' +
      '<h2>访问统计规划中</h2>' +
      '<p>PV / UV 趋势与按人查看的访问审计属于后续里程碑（M5）。' +
      '鉴权站点在边缘验签后已知访问者身份，具备做审计的条件，但数据管道尚未建立——' +
      '所以这里不显示任何数字，避免把空数据当成"没人访问"。</p>' +
      '<p class="meta" style="margin-top:14px">需要临时排查访问情况时，' +
      '可在 CloudWatch 里查该站点的 Lambda 日志组。</p>' +
    '</div></section>';
}

/* ── 危险区域：下线 ─────────────────────────────────────────────────── */

function dangerZone(site) {
  const gone = site.status === 'DELETED';
  /* undeploy 的 CAPABILITIES 是 {owner, admin}——collaborator **不能**下线。 */
  const may = site.role === 'owner' || site.role === 'admin';
  return '<section class="card danger" style="margin-top:28px">' +
    '<div class="card-head"><h2>危险区域</h2>' +
      (may ? '' : '<span class="tag tag-role">仅所有者或平台管理员可操作</span>') + '</div>' +
    '<div class="card-body stack" style="gap:0">' +
      '<div class="row-between" style="padding-bottom:14px">' +
        '<div><div style="font-size:13.5px;font-weight:500">下线站点</div>' +
          '<p class="meta" style="max-width:56ch">删除路由、Lambda 与前端文件，URL 立即不可访问。' +
          '数据库与存储保留，可以重新部署恢复。</p></div>' +
        '<button class="btn btn-danger-quiet" id="undeploy-btn" type="button"' +
          (may && !gone ? '' : ' disabled') + '>' + (gone ? '已下线' : '下线站点…') + '</button>' +
      '</div>' +
      '<hr style="border:0;border-top:1px solid var(--border);margin:0" />' +
      '<div class="row-between" style="padding-top:14px">' +
        '<div><div style="font-size:13.5px;font-weight:500">下线并清除数据</div>' +
          '<p class="meta" style="max-width:56ch">除上述内容外，同时删除站点的数据库内容与' +
          '已上传的文件。<strong>不可恢复。</strong></p></div>' +
        '<button class="btn btn-danger" id="purge-btn" type="button"' +
          (may && !gone ? '' : ' disabled') + '>下线并清除数据…</button>' +
      '</div></div></section>';
}

function bindDangerZone(site) {
  const open = (purge) => {
    const name = site.name || site.site_id;
    const modal = openModal({
      title: purge ? '下线并清除「' + name + '」的全部数据' : '下线站点「' + name + '」',
      desc: purge ? '这个操作不可恢复，请确认无误后再继续。' : '下线后可以重新部署恢复，数据不会丢失。',
      body:
        '<div class="callout ' + (purge ? 'danger' : 'warn') + '">' + ICON.err + '<span>' +
          (purge
            ? '<strong>数据将被永久删除，无法找回。</strong>包括站点数据库内容与已上传的文件。'
            : '<strong>URL 将立即不可访问。</strong>访问者会看到 404；数据库与存储保留，' +
              '重新部署即可恢复。') + '</span></div>' +
        '<dl class="kv" style="grid-template-columns:76px 1fr"><dt>站点</dt>' +
          '<dd class="mono">' + esc(name) + '</dd>' +
          '<dt>URL</dt><dd class="mono">' +
          esc(String(site.url || '').replace(/^https:\/\//, '')) + '</dd></dl>' +
        '<div class="field"><label for="confirm-name">请输入站点名 <span class="mono" ' +
          'style="color:var(--fg)">' + esc(name) + '</span> 以确认</label>' +
          '<input class="input mono" id="confirm-name" placeholder="' + esc(name) +
          '" autocomplete="off" /></div>',
      footer: '<button class="btn" data-close type="button">取消</button>' +
              '<button class="btn btn-danger" id="do-danger" type="button" disabled>' +
              (purge ? '永久删除' : '确认下线') + '</button>'
    });
    const input = $('#confirm-name', modal);
    const btn = $('#do-danger', modal);
    input.addEventListener('input', () => { btn.disabled = input.value.trim() !== name; });
    input.focus();
    $('[data-close]', modal).addEventListener('click', closeModal);
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = '提交中…';
      try {
        /* **异步**：只拿到 job_id + PENDING，真正的删除在后台。
         * 立刻显示"已下线"是错的——刷新会看到站点还在，用户以为失败。 */
        const res = await api('POST', '/api/sites/' + encodeURIComponent(site.site_id) +
          '/undeploy', { purge_data: !!purge });
        closeModal();
        toast('下线已提交', '任务 ' + (res.job_id || '') + ' 正在执行，页面会自动跟进进度', 'info');
        pollUndeploy(site.site_id, res.job_id);
      } catch (err) {
        reportError('提交失败', err);
        btn.disabled = false;
        btn.textContent = purge ? '永久删除' : '确认下线';
      }
    });
  };
  const u = $('#undeploy-btn');
  const p = $('#purge-btn');
  if (u) u.addEventListener('click', () => open(false));
  if (p) p.addEventListener('click', () => open(true));
}

/* 轮询下线进度。**有上限**：无限轮询会在后台任务卡住时一直打接口
 * （每次都是一次 DynamoDB Query），而且用户已经拿到了 job_id，
 * 到点提示他手动刷新比静默转圈更诚实。 */
const POLL_INTERVAL_MS = 4000;
const POLL_MAX_TRIES = 30;      // 约 2 分钟

function pollUndeploy(siteId, jobId, tries) {
  stopPolling();
  const n = tries || 0;
  state.polling = setTimeout(async () => {
    let job = null;
    try {
      const res = await apiGet('/api/sites/' + encodeURIComponent(siteId) + '/jobs');
      job = (res.jobs || []).filter((x) => x.job_id === jobId)[0] || null;
    } catch (err) {
      job = null;
    }
    if (job && (job.status === 'DELETED' || job.status === 'SUCCEEDED')) {
      /* 只有走到这里才是"请求的清理全部完成"。勾了清除数据时，后端在
       * 清理失败的情况下写 PURGE_FAILED 而不是 DELETED，所以这条成功文案
       * 不会误报（Codex 审查 2026-08-10 P1-3）。 */
      toast('站点已下线', '路由与运行时已删除', 'ok');
      if (state.route.page === 'site') pageSite(); else pageSites();
      return;
    }
    /* **站点已下线 ≠ 数据已清除**。用户勾的是"永久删除数据"，清理失败时
     * 绝不能显示删除成功——数据可能还在。这里如实说明并指向管理员。 */
    if (job && job.status === 'PURGE_FAILED') {
      toast('站点已下线，但数据未清理完成',
            job.error || '部分数据可能仍然存在，请联系平台管理员核对', 'err');
      if (state.route.page === 'site') pageSite(); else pageSites();
      return;
    }
    if (job && job.status === 'FAILED') {
      toast('下线失败', job.error || '请查看部署历史里的错误摘要', 'err');
      if (state.route.page === 'site') pageSite();
      return;
    }
    if (n + 1 >= POLL_MAX_TRIES) {
      toast('下线仍在进行', '任务 ' + (jobId || '') + ' 尚未结束，稍后刷新「部署历史」查看结果', 'info');
      return;
    }
    pollUndeploy(siteId, jobId, n + 1);
  }, POLL_INTERVAL_MS);
}

/* ══ 页面 3：API Key（M4）════════════════════════════════════════════
 *
 * 给"只能配静态 Header"的客户端用（支持 OAuth 的客户端不需要 Key）。接的是
 * Task 6 的五个端点：`GET/POST/DELETE /api/keys` 与
 * `GET/PUT /api/settings/api-key`（后两个 admin-only）。
 *
 * ── 明文的生命周期（这一段是本页最要紧的约束）─────────────────────────
 * 明文只在 `POST /api/keys` 的响应里出现**一次**：库里存的是哈希，列表接口的
 * 白名单（api._shape_key）不含它，服务端**没有第二次给它的通道**。所以前端
 * 拿到它之后只做两件事：塞进弹窗的 DOM、按需写进剪贴板。它**不进 state**
 * （下一次渲染会把它带到别的页面上）、**不进 localStorage/sessionStorage**
 * （等于把一个不会过期的凭证留在磁盘上）、**不进地址栏**（URL 会落进浏览器
 * 历史、Referer 与各级代理日志）。
 * tests/test_frontend_contract.py 用"持久化点与地址栏写入点**全量白名单**"
 * 锁这条——而不是"查 plaintext 附近有没有 setItem"：后者被一个中间变量
 * （`const pt = res.plaintext`）就绕过去了。
 */

/* 与 keystore.NAME_MAX 一致。前端更宽 → 用户填完才吃一个 400；前端更严 →
 * 悄悄削掉平台能力。这个数字不该有两份手抄，所以有一条用例从 keystore.py
 * 核对它。 */
const KEY_NAME_MAX = 64;

/* 关闸提示。**是一句说明，不是门禁**：`deployed=true & enabled=false` 是首次
 * 部署后的正常状态，页面必须照常可用（否则管理员无处开闸，见 apiKeyFeature）。*/
const KEY_GATED_NOTE = 'API Key 当前已被管理员全局关闸，新建的 Key 暂时无法调用；' +
  '管理界面照常可用，开闸后既有 Key 立即恢复。';

/* 明文只显示这一次。写成常量而不是散在模板里：这句话是这个功能的**契约**
 * （服务端存哈希，没抄下来只能吊销重发），改它等于改契约。 */
const KEY_ONCE_WARNING = '这是你唯一一次看到完整 Key，关闭后不再显示。';

/* 开关旁的说明。影响面必须写清是**平台级**的：关闸后已经发出去的 Key 全部
 * 立刻失效，不只是"新建的用不了"。 */
const KEY_SWITCH_NOTE = '关闸后所有已发出的 Key 立即失效（网关直接拒绝），' +
  '不只是新建的；开闸后立即恢复。逐把 Key 的吊销在各自所有者手里。';

/* `features.api_key` 的**唯一**读法。
 *
 * 两个字段而不是一个布尔（Codex 审查 2026-08-11 P1-5）：
 *   · `deployed` —— 组件部署了没有。**只有它是 UI 门禁**；
 *   · `enabled`  —— 平台总开关此刻的位置，只驱动提示文案与开关初值。
 * 首次部署强制把哨兵行建成 `enabled=false`，所以"已部署 + 关闸"是部署后的
 * **正常状态**。若按 enabled 做门禁，那一刻页面 disabled 且零请求，管理员没有
 * 任何地方能把闸开回来——部署流程自锁，线上表现是"功能上线了但永远打不开"。
 *
 * 用 `=== true` 而不是真值判断：字段缺失（旧后端）或形态变了一律按 false，
 * 展示层宁可少给入口，也不要请求一批可能不存在的端点。 */
function apiKeyFeature() {
  const f = (state.me && state.me.features && state.me.features.api_key) || {};
  return { deployed: f.deployed === true, enabled: f.enabled === true };
}

async function pageKeys() {
  const view = $('#view');
  renderCrumb([{ label: 'API Key' }]);
  const feat = apiKeyFeature();
  /* 未部署 → **一个请求都不发**：`site-api-keys` 表还不存在，/api/keys 会 500，
   * 那等于把"平台没启用这个功能"翻译成一串看不懂的错误。而这个事实
   * /api/me 已经告诉我们了，不需要再去问一次。 */
  if (!feat.deployed) {
    view.innerHTML = keysHeader() + keysUndeployedCard();
    return;
  }
  view.innerHTML = keysHeader() + skeletonTable(3, 6);

  let keys;
  try {
    const res = await apiGet('/api/keys');
    keys = res.keys || [];
  } catch (err) {
    view.innerHTML = keysHeader() + errorCard('无法加载 API Key 列表', err);
    return;
  }

  /* 开关的**权威值**只从 admin 专属端点取。/api/me 里那份是派生的：它读失败时
   * 会退化成"未部署"（那是控制台的启动请求，不能因为一个功能开关就 500 掉整个
   * 控制台），而给管理员显示一个**位置可能相反**的开关比不显示更糟。这个端点
   * 故意不接 keystore 的读异常——读不出来就报错，见 api.do_get_key_switch。
   * 非 admin 不请求它：后端 _require_admin 会 403。 */
  let sw = null;
  let swErr = null;
  if (state.me.is_admin) {
    try {
      sw = await apiGet('/api/settings/api-key');
    } catch (err) {
      swErr = err;
    }
  }
  const gated = sw ? sw.enabled !== true : !feat.enabled;

  view.innerHTML = keysHeader() +
    (gated ? '<div class="callout warn" style="margin-bottom:16px">' + ICON.err +
      '<span>' + KEY_GATED_NOTE + '</span></div>' : '') +
    keysCreateCard() +
    keysListCard(keys, gated) +
    (state.me.is_admin ? keySwitchCard(sw, swErr) : '');

  bindKeysPage(keys);
}

function keysHeader() {
  return '<section><div style="margin-bottom:20px"><h1>API Key</h1>' +
    '<p class="meta" style="margin-top:4px">给不支持 OAuth 的 Agent 客户端直连 MCP 用：' +
    '把 Key 放进客户端的 <span class="mono">X-API-Key</span> 头，端点是 ' +
    '<span class="mono">mcp.' + baseDomain() + '</span>。' +
    '具体配置见平台的客户端接入指引。</p></div></section>';
}

/* 组件未部署时的整页说明。**纯静态，不发请求**（见 pageKeys 的守卫）。 */
function keysUndeployedCard() {
  return '<section class="card coming-later" aria-disabled="true"><div class="empty">' +
    '<div class="empty-mark">' + ICON.key + '</div>' +
    '<h2>平台尚未启用 API Key</h2>' +
    '<p>这个平台还没有部署 API Key 组件（或读不到它的状态），所以这里既不能创建也' +
    '看不到 Key。支持 OAuth 登录的客户端（Claude Code、Quick Desktop）不需要 Key，' +
    '现在就能直接接入。</p>' +
    '<p class="meta" style="margin-top:14px">平台管理员：组件部署完成后本页会自动可用，' +
    '不需要改前端。</p>' +
  '</div></section>';
}

function keysCreateCard() {
  return '<section class="card" style="margin-bottom:16px">' +
    '<div class="card-head"><div><h2>创建新的 Key</h2>' +
      '<p class="meta" style="margin-top:2px">备注名只给你自己看，用来分辨这把 Key ' +
      '配在哪个客户端上（最长 ' + KEY_NAME_MAX + ' 字）。</p></div></div>' +
    '<div class="card-body"><div class="row" style="gap:8px">' +
      '<input class="input" id="key-name" placeholder="例如：Quick Desktop（工作机）" ' +
        'maxlength="' + KEY_NAME_MAX + '" style="flex:1" />' +
      '<button class="btn btn-primary" id="key-create" type="button">' + ICON.plus +
        '创建 Key</button>' +
    '</div></div></section>';
}

function keysListCard(keys, gated) {
  if (!keys.length) {
    return '<section class="card"><div class="empty">' +
      '<div class="empty-mark">' + ICON.key + '</div>' +
      '<h2>还没有 API Key</h2>' +
      '<p>支持 OAuth 登录的客户端（Claude Code、Quick Desktop）不需要 Key，登录即可。' +
      '只有"只能配静态 Header"的客户端才需要在这里创建一把。</p>' +
    '</div></section>';
  }
  return '<section class="card"><div class="card-head"><div><h2>我的 Key</h2>' +
    '<p class="meta" style="margin-top:2px">共 ' + keys.length +
    ' 把 · 明文只在创建时显示一次，之后这里只能看到前缀</p></div></div>' +
    '<div class="card-body tight"><table class="tbl">' +
    '<thead><tr><th>备注名</th><th>前缀</th><th>创建时间</th><th>最后使用</th>' +
    '<th>状态</th><th style="text-align:right">操作</th></tr></thead><tbody>' +
    keys.map((row) => keyRow(row, gated)).join('') +
    '</tbody></table></div></section>';
}

/* 一行 Key。字段口径 = api._shape_key 的白名单（没有 key_hash，也没有明文）。
 * 备注名是**用户自己填的**，必须过 esc()——控制台是管理界面，在这里执行脚本
 * 就能改权限。 */
function keyRow(row, gated) {
  return '<tr><td>' + esc(row.name) + '</td>' +
    '<td class="mono">' + esc(row.prefix) + '…</td>' +
    '<td class="mono">' + esc(when(row.created_at)) + '</td>' +
    '<td class="mono">' +
      (row.last_used_at ? esc(when(row.last_used_at))
                        : '<span class="meta">从未使用</span>') + '</td>' +
    '<td>' + keyStatusBadge(row, gated) + '</td>' +
    '<td style="text-align:right;white-space:nowrap">' +
      (row.revoked ? '<span class="meta">—</span>'
        : '<button class="btn btn-sm btn-danger-quiet" type="button" data-revoke="' +
          esc(row.key_id) + '">吊销…</button>') +
    '</td></tr>';
}

/* 行内状态。吊销过的就是吊销了（与总开关无关）；没吊销但平台关闸时这把 Key
 * 此刻**调不通**——显示"生效中"是在说谎，所以单独一个"已关闸"的态。 */
function keyStatusBadge(row, gated) {
  if (row.revoked) {
    return '<span class="badge badge-off"><span class="dot"></span>已吊销</span>';
  }
  if (gated) {
    return '<span class="badge badge-warn"><span class="dot"></span>已关闸</span>';
  }
  return '<span class="badge badge-ok"><span class="dot"></span>生效中</span>';
}

/* admin 专属：平台总开关。**只在 state.me.is_admin 时被调用**（见 pageKeys）。
 * 后端还有 _require_admin 兜着，所以这不是安全边界；但一个看得见、一点就 403
 * 的开关是照着来的 bug 报告，也会让普通用户以为自己能关闸。 */
function keySwitchCard(sw, swErr) {
  const head = '<section class="card" style="margin-top:16px">' +
    '<div class="card-head"><div><h2>平台总开关（管理员）</h2>' +
    '<p class="meta" style="margin-top:2px">控制整个平台的 API Key 通道。' +
    '所有开关变更都会记进审计日志（ops-log）。</p></div></div>' +
    '<div class="card-body stack" style="gap:12px">';
  const foot = '</div></section>';
  /* 读不到权威值时**不画开关**：一个位置可能相反的开关比没有开关更危险
   * （管理员以为关着，其实开着）。如实说明并给一次重试。 */
  if (swErr) {
    return head + '<div class="callout danger">' + ICON.err +
      '<span><strong>开关状态读取失败，暂不显示开关。</strong>' +
      esc((swErr && swErr.message) || '未知错误') +
      '</span></div><div><button class="btn" id="key-switch-retry" type="button">' +
      '重试</button></div>' + foot;
  }
  const on = !!(sw && sw.enabled === true);
  return head +
    '<div class="row-between" style="align-items:flex-start">' +
      '<div><div style="font-size:13.5px;font-weight:500">允许用 API Key 调用 MCP</div>' +
        '<p class="meta" style="max-width:52ch">' + KEY_SWITCH_NOTE + '</p></div>' +
      '<button class="switch" id="sw-apikey" role="switch" aria-checked="' + on +
        '" aria-label="API Key 平台总开关"></button></div>' + foot;
}

function bindKeysPage(keys) {
  const create = $('#key-create');
  const input = $('#key-name');

  async function submit() {
    const val = (input.value || '').trim();
    if (!val) {
      toast('请先填备注名', '用来分辨这把 Key 配在哪个客户端上', 'err');
      return;
    }
    /* 长度在后端也会挡（keystore.create → 400）；这里先挡一次是为了少一次
     * 白跑的往返，**不是**唯一防线。 */
    if (val.length > KEY_NAME_MAX) {
      toast('备注名太长', '最长 ' + KEY_NAME_MAX + ' 字', 'err');
      return;
    }
    create.disabled = true;
    create.textContent = '创建中…';
    try {
      const res = await api('POST', '/api/keys', { name: val });
      input.value = '';
      /* 明文只往下传给弹窗（活在那个闭包里）。列表随后刷新一次——弹窗在
       * #modal-root，不受 #view 重渲染影响。 */
      showNewKey(res);
      pageKeys();
    } catch (err) {
      reportError('创建失败', err);
      create.disabled = false;
      create.textContent = '创建 Key';
    }
  }
  create.addEventListener('click', submit);
  input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') submit(); });

  $$('[data-revoke]').forEach((b) => b.addEventListener('click', () => {
    const hit = (keys || []).filter((x) => x.key_id === b.dataset.revoke)[0] || {};
    confirmRevoke(b.dataset.revoke, hit.name, hit.prefix);
  }));

  const sw = $('#sw-apikey');
  if (sw) {
    sw.addEventListener('click', () =>
      setKeySwitch(sw.getAttribute('aria-checked') !== 'true'));
  }
  const retry = $('#key-switch-retry');
  if (retry) retry.addEventListener('click', () => pageKeys());
}

/* 创建结果：明文**完整显示一次** + 复制按钮 + "关闭后不再显示"的警告。
 *
 * 这个函数是明文在前端的唯一落点（见本节开头的"明文的生命周期"）。 */
function showNewKey(row) {
  const modal = openModal({
    title: 'Key 已创建：' + (row.name || ''),
    desc: '把它配到客户端里就能用了。',
    body:
      '<div class="callout warn">' + ICON.err + '<span><strong>' + KEY_ONCE_WARNING +
        '</strong>请立刻复制并存进密码管理器——服务端只存哈希，没有第二次查看的' +
        '通道；丢了只能吊销后重新创建。</span></div>' +
      '<div class="secret"><span style="flex:1">' + esc(row.plaintext) + '</span>' +
        '<button class="btn" id="copy-key" type="button">' + ICON.copy + '复制</button></div>' +
      '<dl class="kv" style="grid-template-columns:76px 1fr">' +
        '<dt>备注名</dt><dd>' + esc(row.name) + '</dd>' +
        '<dt>前缀</dt><dd class="mono">' + esc(row.prefix) + '…</dd>' +
        '<dt>key_id</dt><dd class="mono">' + esc(row.key_id) + '</dd>' +
        '<dt>创建时间</dt><dd class="mono">' + esc(when(row.created_at)) + '</dd></dl>',
    footer: '<button class="btn btn-primary" data-close type="button">我已保存</button>'
  });
  $('[data-close]', modal).addEventListener('click', closeModal);
  $('#copy-key', modal).addEventListener('click', () => {
    if (navigator.clipboard) navigator.clipboard.writeText(row.plaintext);
    /* toast 里**不带明文**：它会在角落多停几秒，而且脱离了这个弹窗
     * "我已保存"的语境。 */
    toast('已复制到剪贴板', '关闭弹窗后这个值不会再出现', 'info');
  });
}

/* 吊销：**发 key_id，不是明文**。key_id 是刻意设计成非秘密标识符的
 * （keygen 的注释），而明文一进请求体就会进沿途每一层日志。
 * 二次确认：使用这把 Key 的客户端会立刻 401，且不可恢复。 */
function confirmRevoke(keyId, name, prefix) {
  const modal = openModal({
    title: '吊销 Key「' + (name || keyId) + '」',
    desc: '吊销后使用这把 Key 的客户端会立刻收到 401。',
    body:
      '<div class="callout danger">' + ICON.err + '<span><strong>此操作不可撤销。</strong>' +
        '还要继续用的话，请创建一把新的 Key 并换到客户端里，再吊销这把。</span></div>' +
      '<dl class="kv" style="grid-template-columns:76px 1fr">' +
        '<dt>备注名</dt><dd>' + esc(name) + '</dd>' +
        '<dt>前缀</dt><dd class="mono">' + esc(prefix) + '…</dd>' +
        '<dt>key_id</dt><dd class="mono">' + esc(keyId) + '</dd></dl>',
    footer: '<button class="btn" data-close type="button">取消</button>' +
            '<button class="btn btn-danger" id="do-revoke" type="button">确认吊销</button>'
  });
  $('[data-close]', modal).addEventListener('click', closeModal);
  const btn = $('#do-revoke', modal);
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = '吊销中…';
    try {
      await api('DELETE', '/api/keys', { key_id: keyId });
      closeModal();
      toast('Key 已吊销', name || keyId, 'ok');
      pageKeys();
    } catch (err) {
      reportError('吊销失败', err);
      btn.disabled = false;
      btn.textContent = '确认吊销';
    }
  });
}

async function setKeySwitch(next) {
  /* 关闸的影响面是**平台级**的（已发出的 Key 全部立刻 401），给一次确认；
   * 开闸不问——它只是把既有能力恢复回去。 */
  if (!next && !window.confirm(
      '关闸后所有已发出的 API Key 立即失效（网关直接拒绝）。确认关闸？')) {
    return;
  }
  const btn = $('#sw-apikey');
  if (btn) btn.disabled = true;
  try {
    /* 发**真布尔**：keystore.set_switch 对 "false" / 0 / null 一律 400
     * （`bool("false") is True` 那个陷阱已经在写入侧钉死了，前端别去试探它）。 */
    await api('PUT', '/api/settings/api-key', { enabled: next });
    toast(next ? 'API Key 通道已开启' : 'API Key 通道已关闸',
          next ? '既有 Key 立即恢复可用' : '所有已发出的 Key 立即失效', 'ok');
    /* 重新拉一次权威值，而不是就地把 aria-checked 拨过去：本地拨一下只是
     * "我以为它变了"。 */
    pageKeys();
  } catch (err) {
    if (btn) btn.disabled = false;
    reportError('开关修改失败', err);
  }
}

/* ══ 页面 4：全局管理（仅管理员）═════════════════════════════════════ */

async function pageAdmin() {
  const view = $('#view');
  renderCrumb([{ label: '平台管理' }]);
  if (!state.me.is_admin) {
    /* 前端这层只是不显示入口；真正的拦截在后端（_require_admin 用强一致读
     * 判定，撤权立即生效）。手敲 #/admin 到这里也拿不到数据。 */
    view.innerHTML = '<div class="card"><div class="empty"><div class="empty-mark">' +
      ICON.shield + '</div><h2>需要平台管理员权限</h2>' +
      '<p>你不在平台管理员名单里，没有全局管理入口。</p>' +
      '<div style="margin-top:18px"><a class="btn" href="#/sites">返回我的站点</a></div>' +
      '</div></div>';
    return;
  }
  view.innerHTML = skeletonPage();

  const f = state.adminFilter;
  let sites = [];
  let admins = [];
  try {
    const both = await Promise.all([apiGet('/api/sites?all=1'), apiGet('/api/admins')]);
    sites = both[0].sites || [];
    admins = both[1].admins || [];
  } catch (err) {
    view.innerHTML = errorCard('无法加载平台管理数据', err);
    return;
  }

  /* owner 下拉从**当前结果集**推导，不额外请求接口（后端没有 listOwners）。 */
  const owners = Array.from(new Set(sites.map((x) => x.owner).filter(Boolean))).sort();
  const needle = f.q.trim().toLowerCase();
  const rows = sites.filter((item) => {
    if (needle && !(item.name + ' ' + item.site_id + ' ' + item.owner)
        .toLowerCase().includes(needle)) return false;
    if (f.status && item.status !== f.status) return false;
    if (f.owner && item.owner !== f.owner) return false;
    return true;
  });

  view.innerHTML =
    '<section><div style="margin-bottom:20px"><h1>平台管理</h1>' +
      '<p class="meta" style="margin-top:4px">全局站点视图与管理员名单 · ' +
      '所有写操作都会记入审计日志（ops-log）</p></div></section>' +

    '<section class="card" style="margin-bottom:16px">' +
      '<div class="card-head"><h2>全局站点</h2><div class="row" style="gap:8px">' +
        '<div class="search" style="width:230px"><span>' + ICON.search + '</span>' +
          '<input class="input" id="a-q" placeholder="搜索站点名 / owner" value="' +
          esc(f.q) + '" /></div>' +
        '<select class="input" id="a-owner" style="width:200px">' +
          '<option value="">全部 owner</option>' + owners.map((o) =>
            '<option value="' + esc(o) + '"' + (f.owner === o ? ' selected' : '') + '>' +
            esc(o) + '</option>').join('') + '</select>' +
        '<select class="input" id="a-status" style="width:120px">' +
          '<option value="">全部状态</option>' + Object.keys(STATUS_LABEL).map((s) =>
            '<option value="' + s + '"' + (f.status === s ? ' selected' : '') + '>' +
            esc(STATUS_LABEL[s]) + '</option>').join('') + '</select>' +
      '</div></div>' +
      '<div class="card-body tight">' + (rows.length
        ? '<table class="tbl"><thead><tr><th>站点</th><th>Owner</th><th>状态</th>' +
          '<th>访问策略</th><th>创建时间</th><th style="text-align:right">操作</th>' +
          '</tr></thead><tbody>' + rows.map((item) => '<tr>' +
            '<td><a class="site-name link" href="#/sites/' + esc(item.site_id) + '">' +
              esc(item.name || item.site_id) + '</a>' +
              '<div class="mono muted" style="font-size:11.5px">' + esc(item.site_id) +
              '</div></td>' +
            '<td><span class="row" style="gap:7px"><span class="avatar sm">' +
              esc(initials(item.owner)) + '</span><span class="mono">' + esc(item.owner) +
              '</span></span></td>' +
            '<td>' + listStatusBadge(item) + '</td>' +
            '<td class="meta">' + esc(policySummary(item)) + '</td>' +
            '<td class="mono">' + esc(when(item.created_at)) + '</td>' +
            '<td style="text-align:right;white-space:nowrap">' +
              '<a class="btn btn-sm" href="#/sites/' + esc(item.site_id) + '">管理</a>' +
            '</td></tr>').join('') + '</tbody></table>'
        : '<div class="empty"><h2>没有符合条件的站点</h2><p>调整搜索词或筛选条件后再试。</p></div>') +
      '</div></section>' +

    '<section class="card"><div class="card-head"><div><h2>管理员名单</h2>' +
      '<p class="meta" style="margin-top:2px">名单内的邮箱登录后会看到「平台管理」入口 · 共 ' +
      admins.length + ' 人</p></div></div>' +
      '<div class="card-body stack" style="gap:12px">' +
        '<div class="taginput" style="min-height:auto">' + admins.map((e) =>
          '<span class="etag">' + esc(e) + '<button type="button" data-rma="' + esc(e) +
          '" aria-label="移除 ' + esc(e) + '">×</button></span>').join('') + '</div>' +
        '<div class="row" style="gap:8px">' +
          '<input class="input mono" id="admin-input" placeholder="name@example.com" ' +
            'style="flex:1" />' +
          '<button class="btn" id="admin-add" type="button">' + ICON.plus + '添加管理员</button>' +
        '</div></div></section>';

  bindSearch('#a-q', (val) => { state.adminFilter.q = val; }, pageAdmin);
  $('#a-owner').addEventListener('change', (ev) => {
    state.adminFilter.owner = ev.target.value; pageAdmin();
  });
  $('#a-status').addEventListener('change', (ev) => {
    state.adminFilter.status = ev.target.value; pageAdmin();
  });

  $$('[data-rma]').forEach((b) => b.addEventListener('click', async () => {
    const target = b.dataset.rma;
    /* 摘掉自己的管理员身份是合法但影响很大的操作（会立刻失去本页入口），
     * 所以给一次确认；后端还有"至少保留一名管理员"的 __count__ 守卫。 */
    if (target === state.me.email && !window.confirm(
        '你正在移除自己的管理员权限，移除后将失去「平台管理」入口。继续？')) {
      return;
    }
    b.disabled = true;
    try {
      await api('DELETE', '/api/admins', { email: target });
      toast('已移出管理员名单', target, 'ok');
      state.me = await apiGet('/api/me');
      renderNav();
      if (state.me.is_admin) pageAdmin(); else go('#/sites');
    } catch (err) {
      b.disabled = false;
      reportError('移除失败', err);
    }
  }));

  async function addAdmin() {
    const input = $('#admin-input');
    const btn = $('#admin-add');
    const val = input.value.trim();
    if (!val) return;
    if (!EMAIL_RE.test(val)) { toast('邮箱格式不正确', val, 'err'); return; }
    btn.disabled = true;
    try {
      await api('PUT', '/api/admins', { email: val });
      toast('已加入管理员名单', val, 'ok');
      pageAdmin();
    } catch (err) {
      btn.disabled = false;
      reportError('添加失败', err);
    }
  }
  $('#admin-add').addEventListener('click', addAdmin);
  $('#admin-input').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') addAdmin(); });
}

/* ══ 启动 ════════════════════════════════════════════════════════════ */

async function render() {
  stopPolling();
  state.route = parseHash();
  if (state.route.page !== 'site') state.draft = null;
  /* **身份没到位就不渲染**：每个页面都读 state.me（is_admin 决定范围与入口），
   * null 上取属性会抛 TypeError 并让页面停在骨架屏。任何在 boot() 取到身份
   * 之前触发的 hashchange 都会走到这里——与其崩，不如什么都不做，等 boot
   * 自己 render()。这条兜底是"不变量集中在一处"，而不是在四个页面各写一次。 */
  if (!state.me) return;
  renderNav();
  if (state.route.page === 'keys') return pageKeys();
  if (state.route.page === 'admin') return pageAdmin();
  if (state.route.page === 'site') return pageSite();
  return pageSites();
}

window.addEventListener('hashchange', () => { closeModal(); render(); });

$('#logout-btn').addEventListener('click', () => {
  openModal({
    title: '登出控制台',
    desc: '登出后需要重新通过公司 SSO 登录。',
    /* 措辞不能承诺"已完全退出"：auth 的 /logout 会结束平台会话与 Cognito
     * 托管会话，但**不会**登出上游 IdP（login_handler 的注释里有官方依据）。 */
    body: '<p class="meta">已部署的站点不受影响，仍可正常访问。' +
          '企业身份提供方（如飞书）的会话不在此处结束——共享设备上请一并退出它。</p>',
    footer: '<button class="btn" data-close type="button">取消</button>' +
            '<button class="btn btn-primary" id="do-logout" type="button">确认登出</button>'
  });
  $('[data-close]').addEventListener('click', closeModal);
  $('#do-logout').addEventListener('click', () => {
    try {
      localStorage.removeItem(UPGRADE_MARK);
    } catch (e) { /* 无所谓 */ }
    location.assign(authOrigin() + '/logout');
  });
});

$('#user-chip').addEventListener('click', () => {
  if (!state.me) return;
  toast(state.me.email, (state.me.name || '') +
    (state.me.is_admin ? ' · 平台管理员' : ' · 通过公司 SSO 登录'), 'info');
});

(async function boot() {
  /* 从升级跳转回来：补上标记并回到原来的位置（整页跳转会丢 hash）。
   *
   * **不能在这里 return**：改 hash 是**同文档导航**，浏览器不会重新加载页面、
   * 不会重新执行本脚本，只会触发 hashchange。提前 return 的话 boot 再也不会
   * 继续，`state.me` 永远是 null，而 hashchange → render() → pageSites() 立刻
   * 在 `state.me.is_admin` 上抛 TypeError——用户看到骨架屏卡死。
   * （实测确认过这个形态；此处原先的注释"location.replace 会重新执行 boot"是错的。）
   *
   * 所以：先把 hash 摆正（此时还没有 hashchange 监听器之外的副作用），
   * 再照常往下走取身份，最后由 boot 自己 render()。
   */
  let cameBack = false;
  try {
    cameBack = !!sessionStorage.getItem(UPGRADE_BACK);
  } catch (e) { cameBack = false; }
  if (cameBack) {
    markUpgraded();
    restoreAfterUpgrade();      // 只摆正 hash，**不 return**
  }

  try {
    state.me = await apiGet('/api/me');
  } catch (err) {
    /* 未登录时 Edge 就已经 302 到登录页了，走不到这里。真到了这里说明
     * panel 本身有问题——如实说明，不要显示一个空壳控制台。 */
    document.getElementById('view').innerHTML =
      errorCard('控制台加载失败', err);
    return;
  }

  /* 在用户还没开始操作时先把面板会话拿到：升级是整页跳转，等到写请求
   * 401 才跳会把填好的表单丢掉。标记只是本地提示，判定权在服务端。 */
  if (!hasFreshUpgradeMark()) {
    if (goUpgrade(location.hash)) return;
  }
  render();
})();
