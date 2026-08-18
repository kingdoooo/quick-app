"""SFN 终态：成功/失败落账 + 站点记录维护 + 前端旧版本与 Lambda 旧版本清理。

提交点之后（register_route 那一次 put_item 之后）只剩 smoke_test，所以本文件的
失败分支承担**补偿**：把路由按 `event["previous_route"]` 还原。
"""
import logging
import os
from datetime import timedelta

import boto3

import common
import permissions
# blue/green 的颜色词表**只有一处定义**（deploy_lambda_site.COLORS）。这里 import
# 而不是再抄一份 ("blue", "green")：抄第二份之后，加第三个颜色或改名时清理逻辑会
# 静默地只看旧的两个 —— 而"漏看一个颜色"在这里的后果是删掉它正在用的版本。
from deploy_lambda_site import COLORS

logger = logging.getLogger()

# 除 alias 引用的版本之外，再留最近这么多个：回滚要有落点。
KEEP_RECENT_VERSIONS = 3

# 前端版本前缀：年龄小于这个值的一律不删——可能是同一站点另一次**正在跑**的部署
# 刚上传完的那一份。取状态机的整体超时（infra/app.py 的 TimeoutSeconds=1800），
# 超过它的 execution 一定已经不在跑了。理由详见 `_cleanup_old_versions`。
KEEP_PREFIX_MINUTES = 30


def _lambda():
    return boto3.client("lambda")


# 补偿被放弃时写进 **job 错误信息**的说明。只 logger.error 不够：看到部署失败的人
# 看的是 job 记录，CloudWatch 里那行他们看不到，而"路由没回滚"是需要人去处置的。
ROUTE_NOT_ROLLED_BACK = (
    "路由未回滚，仍停在本次部署的新目标上：线上的路由已不是本次部署提交的那一份"
    "（冒烟期间有人改过站点权限、站点被下线，或同一站点另有一次更晚的部署已经"
    "提交）。强行回滚会把旧权限写回、让已下线的站点复活、或覆盖掉那次更晚的部署，"
    "因此放弃——需人工介入。")

# 与上面那条**不是一回事**，措辞必须分开：上面是"条件判定为不该回滚"（一个正确的
# 决定），这里是"想回滚但请求本身失败了"（AWS 报错、限流、权限）。两者的处置不同
# ——前者要看是谁改的，后者要重试/查配额。混用一条文案会把排查引向错误方向。
ROUTE_RESTORE_FAILED = (
    "路由回滚请求失败（AWS 调用报错），路由可能仍停在本次部署的新目标上——"
    "需人工核对路由表并手工恢复。详细错误见 CloudWatch。")

# 第三种：路由确实切过，但补偿所需的快照没随事件传到这里。正常情况下不会发生
# （快照与路由提交同一笔事务落进 job 记录，见 common.route_commit_item），所以
# 看到这条说明有更深的问题——但**必须如实说出来**，不能因为"理论上不该发生"就静默。
ROUTE_SNAPSHOT_LOST = (
    "路由已切到本次部署的新目标，但回滚所需的切换前快照未随任务传递，无法自动"
    "回滚——需人工核对路由表。这不该发生，请一并检查 register_route 的日志。")


def _route_equals(ddb, subdomain: str, expected: dict) -> bool:
    """线上这条路由是不是**逐字节**等于 `expected`。

    只用来分辨"幂等终态"，所以读失败一律当"不相等"：宁可多报一条需人工核对，
    也不要因为一次读超时就把"没回滚"说成"已经回滚好了"。
    """
    try:
        item = ddb.get_item(TableName=os.environ["ROUTING_TABLE"],
                            Key={"subdomain": {"S": subdomain}},
                            ConsistentRead=True).get("Item")
    except Exception as e:      # noqa: BLE001
        logger.error(f"读回路由核对失败: {e}")
        return False
    return item == expected


def _route_absent(ddb, subdomain: str) -> bool:
    """线上这条路由已经不存在了吗（同上，读失败当"还在"）。"""
    try:
        return "Item" not in ddb.get_item(
            TableName=os.environ["ROUTING_TABLE"],
            Key={"subdomain": {"S": subdomain}}, ConsistentRead=True)
    except Exception as e:      # noqa: BLE001
        logger.error(f"读回路由核对失败: {e}")
        return False


def _restore_route(event) -> str | None:
    """把路由还原到本次部署切换之前。**`previous_route` 是三态契约**，
    见 `register_route` 里那段注释：

    · 键**不在**       = register_route 还没提交 ⇒ 线上从未变过，动它才是制造故障；
    · 键在、值 `None`  = 提交过，但切换前没有路由（首次部署）⇒ 删掉刚写的那条；
    · 键在、值是 item  = 提交过且有上一版 ⇒ **整值**写回。

    写成 `if not prev: return` 会把前两态合并，于是首次部署失败后那条指向失败站点
    的路由会留在线上——用户拿到的 URL 打开是一个部署失败的站点而不是 404。

    整值写回而不是挑字段：挑字段会丢掉 route_mode / require_auth / allowed_users /
    collaborators / permissions_rev……而 Edge 对缺失字段按默认值回落 = 一次静默的
    策略变更（可能是扩权）。

    失败仅告警：此刻已经在失败分支里，抛异常只会用"恢复也失败了"盖掉原始错误。
    但**必须如实回报**：AWS 调用真的失败时返回 `ROUTE_RESTORE_FAILED`，
    只写 CloudWatch 不写 job 记录的话，操作者读到的是"部署失败了"，而不知道那条
    失败的新路由还在线上服务（Codex 2026-08-17 P2）。

    **写回必须带条件**：快照是提交那一刻拍的，而 smoke 有几十秒。这段时间里线上
    可能已经变了，三条都可达：
      · 有人在线收紧权限（`permissions.py` 是"sites 推 rev + 改路由"同一事务）
        ⇒ 无条件整值写回会把 allowed_users 一起写回收紧**之前**的样子，
        fail-open 扩权，而且只 warning ⇒ 静默；
      · 站点被下线（`undeploy.py` 删掉这一行）⇒ 写回等于让一个已删除的站点的
        子域名重新可路由，把"已删除"撤销了；
      · **同一站点另有一次更晚的部署已经提交**（部署租约只挡新执行的**创建**，
        存量在跑的执行仍可能交错）⇒ 写回会把那次成功的部署整条覆盖掉。

    条件由 `permissions.committed_route_condition` 给出（全仓库唯一定义），
    语义是"线上这条路由**还是我这次部署提交进去的那一份**"：
    `static_prefix`（带 job_id ⇒ 天然唯一）+ 本次写入的 `permissions_rev`。
    **锚点选在提交端而不是快照端**，理由与两条实测缺陷的对应关系见该函数的
    docstring；这里只记结论：锚快照 rev 既认不出并发部署（两个 job 的快照 rev
    相同），也让存量的 rev-less 路由永远无法回滚。

    条件失败 = 世界变过了 ⇒ **放弃**，不重试、不挑字段合并（挑字段会丢掉
    route_mode / require_auth / collaborators……而 Edge 对缺失字段按默认值回落，
    等于一次静默的策略变更）。返回一句说明由 handler 写进 job 错误信息。

    **没有 `committed_permissions_rev` ⇒ 直接放弃**（不退回快照 rev 那套）：
    只有升级窗口里老代码起的 execution 会缺它。此刻没有可锚的提交端，而快照端
    那套恰是本次改动认定不可靠的那一套——退回去等于在最不该的时候用一个已知有
    洞的守卫。放弃 + 如实告知，代价只是那几分钟内的失败部署要人工看一眼。

    **值为 `None` 那一态（首次部署 ⇒ 删掉）不带条件，这个不对称是有意的**：
    删除不写回任何权限值，它比任何权限状态都更"关"（子域名直接不解析）；被丢掉的
    只是权限的**投影**，而真源在 sites 表里还在（`permissions.py` 本来就有
    `_ALLOW_ROUTE_ABSENT` 这条"站点还没首次部署成功"的路径，下次部署会重新投影）。
    反过来给删除加条件的代价是实打实的：条件一失败，一个 FAILED 的首次部署就把
    子域名继续占着、指向一个坏站点——那正是这一态存在的理由。
    """
    subdomain = common.subdomain_for(event["site_id"])
    mine = common.static_prefix_for(event["site_id"], event["job_id"])
    if ("previous_route" not in event
            or event.get("committed_permissions_rev") is None):
        # **事件里缺补偿状态 ≠ 没提交过**（独立评审 2026-08-18 Important-2）：
        # SFN 的 add_catch 用 result_path 把错误**并进失败那个 Task 的输入**，
        # 所以 RegisterRoute 提交成功后若全部重试仍失败（例如 transact 落地后
        # 进程被杀、随后每次重试都栽在回放读上），MarkFailed 拿到的是
        # upload_frontend 的输出——两个补偿字段都不在。而 job 里有与提交**同一笔
        # 事务**落库的 route_commit，那才是真源。所以缺字段先读它：
        #   · 读到了 ⇒ 用它补齐，走完整补偿（不读的话这里只能报"需人工介入"，
        #     而系统明明有能力自动回滚——正是本轮改动要满足的那条要求）；
        #   · 没有 ⇒ 确实从未提交（或老代码起的 execution），走下面的分支。
        try:
            commit = common.read_route_commit(event["job_id"])
        except Exception as e:      # noqa: BLE001
            # **读失败 ≠ 没提交**（Codex 2026-08-18 R5 P1）：此刻既不知道路由
            # 是否提交过、也不知道要不要恢复——把它折叠成 None 会让 handler
            # 照常写 FAILED、放开租约，新部署在一条状态未知的路由上开跑。
            # 返回 RESTORE_FAILED ⇒ handler 抛出 ⇒ 保持 RUNNING，重试预算
            # 交给 SFN；重试耗尽由 sweeper 收敛并如实写 note（最后一环）。
            logger.error(f"读 route_commit 失败: {e}")
            return ROUTE_RESTORE_FAILED
        if commit is not None:
            prev_av = commit["previous_route"]
            event = dict(event)     # 不改调用方的 event（handler 还要用它落账）
            event["previous_route"] = (None if "NULL" in prev_av
                                       else prev_av["M"])
            event["committed_permissions_rev"] = int(
                commit["committed_route"]["M"]["permissions_rev"]["N"])
    if "previous_route" not in event:
        # route_commit 读到了但为空 ⇒ **通常**意味着 register_route 还没提交
        # （route_commit 与路由提交同一笔事务，缺席即未提交——对新代码是权威的）。
        # 但升级窗口里老代码起的 execution 没有这条记录，所以仍看一眼线上：
        # 前缀若是本 job 写的，提交确实发生过 ⇒ 如实告知，不能静默把
        # "路由停在失败的新目标上"藏起来。
        try:
            live = boto3.client("dynamodb").get_item(
                TableName=os.environ["ROUTING_TABLE"],
                Key={"subdomain": {"S": subdomain}},
                ConsistentRead=True).get("Item") or {}
        except Exception as e:      # noqa: BLE001
            # 与上面同一条纪律（R5 P1）：这次读是判定"提交过没有"的最后依据，
            # 读失败 = 状态未知，不能折叠成"无需补偿"。
            logger.error(f"确认路由现状失败: {e}")
            return ROUTE_RESTORE_FAILED
        if live.get("static_prefix", {}).get("S") == mine:
            logger.error(f"{subdomain}: 快照缺席但路由已是本次部署的目标 —— "
                         f"{ROUTE_SNAPSHOT_LOST}")
            return ROUTE_SNAPSHOT_LOST
        return None
    prev = event["previous_route"]
    try:
        ddb = boto3.client("dynamodb")
        if prev is None:
            # **首次部署的删除同样要带提交端条件**（Codex 2026-08-17 P1-2）：
            # 无条件删会让一个更晚的成功部署被这条失败的首次部署顺手删掉——
            # 同站点两个 job 可以同时在跑（M7 加固后由部署租约挡住，但租约挡的是
            # 新执行的**创建**，存量在跑的执行仍可能交错），而"整条路由消失"比
            # "路由停在旧目标"更糟：子域名直接不解析。
            #
            # 条件用与下面那条完全相同的 `committed_route_condition`——这一态和
            # 那一态要判定的是同一件事（"线上这条还是我提交的那份吗"），
            # 两处各写一份条件就是同一不变量的第二个副本。
            #
            # 原先此处刻意不带条件，理由是"删除比任何权限状态都更关，而条件一失败
            # 就让 FAILED 的首次部署继续占着子域名"。那条权衡是针对**快照端** rev
            # 条件的（在线改权限就会让它失败）。换成提交端锚点之后，条件失败只剩
            # 三种情形：更晚的部署已提交（绝不能删）、路由已被 undeploy 删掉
            # （没什么可删）、冒烟期间有人在线改过权限（此时路由的权限是新的、
            # 且它指向的后端过了健康门，留着并如实告知比删掉更好）。
            committed_rev = event.get("committed_permissions_rev")
            if committed_rev is None:
                logger.error(f"{subdomain}: {ROUTE_NOT_ROLLED_BACK}")
                return ROUTE_NOT_ROLLED_BACK
            expr, values = permissions.committed_route_condition(
                static_prefix=mine, rev=int(committed_rev))
            try:
                ddb.delete_item(TableName=os.environ["ROUTING_TABLE"],
                                Key={"subdomain": {"S": subdomain}},
                                ConditionExpression=expr,
                                ExpressionAttributeValues=values)
            except ddb.exceptions.ConditionalCheckFailedException:
                # 幂等终态：本步骤被重试时第一次已经删掉了，条件自然不成立。
                # 那不是"没回滚"，而是"已经回滚完了"——报成前者会让操作者去处置
                # 一个并不存在的问题（Codex 2026-08-17 P2）。
                if _route_absent(ddb, subdomain):
                    logger.warning(f"{subdomain} 的路由已不存在（本次或前一次尝试"
                                   "已撤掉），无需再删")
                    return None
                logger.error(f"{subdomain}: {ROUTE_NOT_ROLLED_BACK}")
                return ROUTE_NOT_ROLLED_BACK
            logger.warning(f"首次部署失败，已撤掉 {subdomain} 的路由")
            return None
        committed_rev = event.get("committed_permissions_rev")
        if committed_rev is None:
            # 升级窗口（见上）⇒ 放弃，而且**一次写请求都不发**：没有可锚的提交端时
            # 任何条件都只能是猜，发出去只是消耗配额、并在 CloudWatch 里留一条会被
            # 误读成"恢复失败"的噪声。
            logger.error(f"{subdomain}: {ROUTE_NOT_ROLLED_BACK}")
            return ROUTE_NOT_ROLLED_BACK
        # **条件表达式走 permissions.committed_route_condition（全仓库唯一定义），
        # 不在这里手写**。`tests/test_permissions.py::
        # test_no_handwritten_rev_guard_outside_permissions_module` 按 AST 扫源码
        # 钉死这一点，理由是本函数上面讲的那个坑的另一面：手抄第二份之后，
        # "兼容分支静默成立"的形态会在第二处复活（仓库里两个 P1 都是这么来的）。
        #
        # static_prefix 同样走 common 的唯一定义：这里要比的必须与
        # `register_route._route_item` 写进去的**逐字节同义**，各写一份 f-string
        # 的话，尾斜杠或段序一改就变成"条件永远不成立"（恢复静默停摆）。
        expr, values = permissions.committed_route_condition(
            static_prefix=common.static_prefix_for(event["site_id"],
                                                   event["job_id"]),
            rev=int(committed_rev))
        try:
            ddb.put_item(TableName=os.environ["ROUTING_TABLE"], Item=prev,
                         ConditionExpression=expr,
                         ExpressionAttributeValues=values)
        except ddb.exceptions.ConditionalCheckFailedException:
            # **先分辨"已经恢复好了"这个幂等终态**（Codex 2026-08-17 P2）：
            # MarkFailed 自己也带默认 Task 重试，第一次成功写回之后，第二次的条件
            # 必然不成立（线上已经是旧路由，不再是我提交的那份）。把它报成
            # "路由未回滚、需人工介入"是**谎报**——路由其实好着，而这条提示会让人
            # 去处置一个不存在的问题，下次真出问题时也就不再被当真。
            if _route_equals(ddb, subdomain, prev):
                logger.warning(f"{subdomain} 的路由已经是切换前那份（本次或前一次"
                               "尝试已恢复），无需再写")
                return None
            logger.error(f"{subdomain}: {ROUTE_NOT_ROLLED_BACK}")
            return ROUTE_NOT_ROLLED_BACK
        logger.warning(f"已把 {subdomain} 的路由整值恢复到切换前")
        return None
    except Exception as e:      # noqa: BLE001
        # 如实回报（见 docstring）：吞成 None 会让 job 记录只说"部署失败"，
        # 而那条失败的新路由还在线上服务，没人知道要去处置它。
        logger.error(f"路由恢复失败（需人工介入）: {e}")
        return ROUTE_RESTORE_FAILED


def _cleanup_versions(site_id: str, *, keep_extra=()) -> None:
    """删掉没人引用的旧 Lambda 版本。保留：两个 alias 当前引用的 + 最近
    `KEEP_RECENT_VERSIONS` 个 + `keep_extra`（本次刚部署的那个）。

    健康门失败留下的版本会被这里收走（否则永久占账号的代码存储配额）。

    **`keep_extra` 不是冗余**：alias 的读与"刚把 alias 指过去"之间有一个瞬间，读到
    旧值时 keep 里就没有本次的版本号，而它可能恰好落在"没人引用且不在最近 N 个"里
    ⇒ 被删。传进来的这一个不依赖读一致性。

    **失败一律整体放弃，不做部分清理**：站点已上线，残留版本只是配额；而 keep 集合
    只要少一个版本就可能删掉**线上 alias 正指着的**那个 —— 那是站点当场 500。所以
    只有"该色不存在"（`ResourceNotFoundException`）算作"这一色没有要保留的版本"，
    其余任何原因（限流、超时、权限）都让整个清理放弃。宽 `except Exception: pass`
    恰好把这两种原因混成一种。
    """
    fn = f"site-{site_id}"
    lam = _lambda()
    try:
        keep = {str(v) for v in keep_extra if v}
        for c in COLORS:
            try:
                keep.add(lam.get_alias(FunctionName=fn, Name=c)["FunctionVersion"])
            except lam.exceptions.ResourceNotFoundException:
                pass        # 该色还不存在（迁移中的站点只有一个颜色）
        # **只收纯数字的版本号**：`$LATEST` 必须排除（删它 = 删函数配置里的当前
        # 代码），而任何非版本号字符串既会让 sort(key=int) 抛错、又会变成
        # delete_function 的一个危险 Qualifier。
        nums = []
        for page in lam.get_paginator("list_versions_by_function").paginate(
                FunctionName=fn):
            nums += [v["Version"] for v in page["Versions"]
                     if str(v["Version"]).isdigit()]
        nums.sort(key=int)
        # 注意 `nums[-0:]` 是**整个列表**而不是空：把 KEEP_RECENT_VERSIONS 设成 0
        # 的效果是"全部保留"（清理停摆），不是"一个都不留"。这个方向是安全的
        # （宁可多留也不误删），所以不去"修"它——但别照字面读成"保留 0 个"。
        keep |= set(nums[-KEEP_RECENT_VERSIONS:])
        for v in nums:
            if v not in keep:
                # Qualifier 必须带且必须是版本号：**不带 Qualifier 就是删整个
                # 函数**，站点当场消失。
                lam.delete_function(FunctionName=fn, Qualifier=v)
    except Exception as e:      # noqa: BLE001
        logger.warning(f"旧版本清理失败（不影响部署结果）: {e}")


def _utcnow():
    """模块级，好让用例把"现在"推到未来，把已有对象变成"陈旧"的。
    moto 不允许指定 LastModified，所以按对象年龄分支的用例只能从这一端注入。"""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def _cleanup_old_versions(site_id: str, current_job_id: str,
                          previous_prefix: str | None = None):
    """删除 sites/{site_id}/ 下的陈旧前端版本前缀。失败仅告警——站点已上线，
    残留旧版本只是存储成本。

    **保留三类，每一类都对应一个真实故障，不是保守裕量**：

      ① 本次 job 的前缀 —— 线上正在服务的那一份。

      ② `previous_prefix`（上一版正在服务的那一份，由 `event["previous_route"]`
         给出）。**这是 M7"原子切换"成立的必要条件**：切路由是一次 put_item，
         但 Edge 每个实例把整条路由 item 缓存 60s
         （`origin_request.ROUTE_CACHE_TTL`），提交之后仍有 warm 实例按**旧**
         `static_prefix` 改写请求。旧前缀被立刻删掉 ⇒ 那些实例打到一个不存在的
         对象上，而前端桶是私有的 ⇒ 浏览器拿到的是 **403 而不是 404**，最长持续
         约 60s（Codex 2026-08-17 P1-1）。留到下一次部署再删，那时它早已不被任何
         缓存引用。
         注意后端不受这条影响：旧色的 alias / URL / 版本由 `_cleanup_versions`
         按 alias 引用保留，本来就还在。

      ③ 年龄小于 `KEEP_PREFIX_MINUTES` 的前缀 —— 可能是**同一站点另一次正在跑的
         部署**刚上传完、还没提交路由的那一份（部署租约只挡新执行的**创建**，
         存量在跑的执行仍可能交错）。删掉它，那次部署随后提交的路由会指向一个空前缀，站点
         整站 403。阈值取状态机的整体超时（TimeoutSeconds=1800），因为超过它的
         execution 一定已经不在跑了 —— 上界来自系统里已有的那个数，不是猜的。

    这三类之外一律删。删不掉只是存储成本；**删错一个就是线上 403**，所以判据
    宁可多留。前端桶不再配 `sites/` 的生命周期规则（那条规则会连线上那一份一起
    删，见 upload_frontend 的模块 docstring），存储上界由本函数提供。
    """
    try:
        s3 = boto3.client("s3")
        bucket = os.environ["FRONTEND_BUCKET"]
        root = common.site_prefix_for(site_id)
        keep = {common.static_prefix_for(site_id, current_job_id) + "/"}
        if previous_prefix:
            # 路由表里的 static_prefix **不带**尾斜杠，而下面的 `keep` 是拿**整个
            # 分组键**（一定以 `/` 结尾）去比相等的，所以这里必须补上——不补就是
            # `p in keep` 永远为假，"要保的那一个"每次都被删。
            #
            # 归属判定用"按段切分 + 相等"而不是 `startswith`：后者会让
            # `sites/s/job-1` 命中 `sites/s/job-11/...` 的对象，删除范围随 job_id
            # 的字面前缀关系漂移（症状是"偶尔删错，换个 job_id 就好了"）。
            keep.add(previous_prefix.rstrip("/") + "/")
        cutoff = _utcnow() - timedelta(minutes=KEEP_PREFIX_MINUTES)
        groups, newest = {}, {}
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=root):
            for o in page.get("Contents", []):
                rel = o["Key"][len(root):]
                if "/" not in rel:
                    # 直接躺在 sites/{site_id}/ 下、不属于任何版本前缀的对象。
                    # 按构造不该存在（upload_frontend 只往 job 前缀里写），
                    # **不删**：分不清归属时删除是不可逆的，而留着只是存储。
                    continue
                p = root + rel.split("/", 1)[0] + "/"
                groups.setdefault(p, []).append({"Key": o["Key"]})
                mtime = o["LastModified"]
                if p not in newest or mtime > newest[p]:
                    newest[p] = mtime
        stale = []
        for p, objs in groups.items():
            if p in keep or newest[p] > cutoff:
                continue
            stale += objs
        for i in range(0, len(stale), 1000):
            s3.delete_objects(Bucket=bucket, Delete={"Objects": stale[i:i + 1000]})
    except Exception as e:
        logger.warning(f"旧版本清理失败（不影响部署结果）: {e}")


def handler(event, context):
    job_id = event["job_id"]
    if "error_info" in event:
        cause = str(event["error_info"].get("Cause", "未知错误"))[:500]
        # **补偿在前、终态在后**（Codex 2026-08-18 R4 P1-1）。顺序不是风格问题：
        # 部署租约判"忙"的依据是 holder 的 status == RUNNING，status 一写成
        # FAILED 租约即可被抢——若此刻补偿还没跑完，新部署 B 会在"A 已提交但
        # 未回滚"的路由上算 live/idle 色，随后 A 的补偿把路由写回旧色，而那个
        # 旧色的 alias 可能正被 B 指向一个**还没过健康门**的新版本。保持 RUNNING
        # 到补偿结束 = 租约把 B 挡在外面，交错不存在。
        #
        # 原先"先落账再补偿"的理由是"补偿卡死时 job 不该停在 RUNNING"——那条
        # 理由已经过时：MarkFailed 抛错会被 SFN 重试（补偿幂等），重试耗尽 ⇒
        # execution FAILED ⇒ sweeper ≤45 分钟收敛（收敛前同样先补偿）。期间
        # 租约一直挡着新部署，这正是"路由状态未定"时该有的方向。
        # "失败已被记录"由 phase + error 满足（用户看得到错因，只是还没终态）。
        common.update_job(job_id, phase="compensating", error=cause)
        note = _restore_route(event)
        if note == ROUTE_RESTORE_FAILED:
            # 回滚的 AWS 调用**本身**失败（暂时性失败的典型形态）⇒ 抛出，让 SFN
            # 重试整个 MarkFailed（补偿幂等）。写 FAILED 就是放开租约让新部署在
            # 一条未回滚的路由上开跑——路由状态未定时保持 RUNNING 才是对的。
            # 重试耗尽 ⇒ execution FAILED ⇒ sweeper 以 45 分钟节奏再试，
            # 它那条路径在补偿仍失败时会收敛并把同一条 note 如实写进 job
            # （见 reconcile_job._compensate_then_converge——那里是**最后一环**，
            # 只能收敛加如实告知，再"保持 busy"就是永久锁站）。
            raise RuntimeError(f"{ROUTE_RESTORE_FAILED}（原始错因：{cause[:150]}）")
        if note:
            # 补偿被放弃是**可操作**信息，必须落到用户看得见的地方（job 记录）。
            # 截断时砍**原因**、不砍这条提示：提示被截掉就等于没写。
            cause = f"{cause[:max(0, 500 - len(note) - 3)]} | {note}"
        common.update_job(job_id, status="FAILED", error=cause)
        return {"job_id": job_id, "status": "FAILED", "error": cause}

    common.update_job(job_id, status="SUCCEEDED", url=event["url"])
    # 不写 owner：jobs 表的 owner 字段是**发起者**（requested_by 语义），
    # 而站点 owner 只由 permissions.transfer_owner 与首次部署的
    # do_deploy_site 写。二期放开 collaborator 部署后，把发起者写回站点
    # owner 会让协作者部署一次就夺取所有权（spec §3.3.1）。
    common.upsert_site(event["site_id"], status="ACTIVE", last_job_id=job_id,
                       tier=event["manifest"]["tier"],
                       name=event["manifest"]["name"],
                       subdomain=common.subdomain_for(event["site_id"]))
    # 上一版正在服务的前缀要**留一轮**：Edge 每个实例把路由缓存 60s，提交之后仍有
    # warm 实例按旧 static_prefix 改写请求，立刻删掉就是最长约 60s 的 403
    # （详见 `_cleanup_old_versions` 的 ②）。`previous_route` 由 register_route 在
    # 提交前拍下，成功路径上同样在 event 里；首次部署时是 None。
    prev = event.get("previous_route") or {}
    _cleanup_old_versions(
        event["site_id"], job_id,
        previous_prefix=prev.get("static_prefix", {}).get("S"))
    # 清理**只在成功分支**做：失败分支要靠旧色 alias、旧色 URL、旧前端前缀都还在
    # 才能完整恢复（register_route 那段注释里的同一条理由）。
    _cleanup_versions(event["site_id"],
                      keep_extra=(event.get("deploy_version"),))
    return {"job_id": job_id, "status": "SUCCEEDED", "url": event["url"]}
