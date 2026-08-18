# 多用户与数据隔离机制

> 本文档说明 `dsh-server-deployment` 网关如何为每个用户提供**独立的 DSH 实例**与 **OS 级数据隔离**，以及文件访问助手的安全模型（含 issue #1 TOCTOU 竞态的修复方案）。

## 1. 威胁模型

网关部署在**远程服务器**上，多个用户通过浏览器（公网域名 + HTTPS 反向代理）访问各自的会话与交付文件。需要防范：

- **用户间越权**：用户 A 读取 / 修改用户 B 的会话、文件或 API Key。
- **文件逃逸**：用户通过下载 / 上传接口访问 `/opt/deepseek-harness` 之外的任意路径（如 `/etc/passwd`、其他用户的目录）。
- **网关沦陷放大**：一旦网关进程被攻破，攻击者不应直接获得任意用户的文件读写能力。
- **竞态（TOCTOU）**：root 助手在“校验参数”与“实际读写”之间被并发替换符号链接 / 路径，导致越界访问。

核心原则：**隔离以 OS 账号为边界，而非以网关代码为边界**。网关对用户数据零权限，所有文件操作经由 sudo 助手以目标用户身份执行。

## 2. 隔离层次

```
浏览器 ──https──▶ TLS 反代 ──▶ dsh-gateway ──▶ 每用户 DSH 实例 dsh-<name>
                                    │
                                    └─ 文件操作经 sudo 助手降权为 dsh-<name> 执行
```

| 层次 | 机制 | 说明 |
|---|---|---|
| 网络边界 | 仅监听 `127.0.0.1` | 网关与所有实例不暴露公网端口，公网只走 TLS 反代 |
| 回环隔离 | iptables `DSH_LOOPBACK_GUARD` 链 | 每个租户 OS 账号只能连自己的实例端口；跨租户端口与网关端口被 REJECT（防伪造 Host 直连他人实例窃取 Key） |
| 实例隔离 | 每用户独立 DSH 实例、独立端口 | `userctl.js add <name>` 自动分配端口并启动实例 |
| 账号隔离 | 每用户独立 OS 账号 `dsh-<name>` | `DSH_HOME` 指向该用户的 0700 私有目录 |
| 资源限制 | systemd TasksMax / MemoryMax / CPUQuota | 单个租户的失控 agent 不至于拖垮整机与其他租户 |
| 凭据隔离 | `.credentials.yaml` 0600 属主仅本人 | API Key 经回环 RPC 写入用户私有目录，DSH 启动时强制检查 `assertOwnerOnly` |
| 会话隔离 | HMAC 签名会话 Cookie（内嵌 pwdVer）+ 每用户实例绑定 | Cookie 防篡改；改密后 pwdVer 递增，旧令牌全部失效 |
| 文件访问 | sudo 助手 + `runuser` 降权 | root 仅校验参数，文件操作以 `dsh-<name>` 自身身份执行（见下） |

## 3. 文件访问助手的安全模型（issue #1 TOCTOU 修复）

历史方案中 root 助手被授予“校验 + 读写”双重职责：root 先做 realpath 前缀校验，若通过则以 root 身份读写。这存在 TOCTOU 竞态——校验与读写之间的路径可被并发替换（如符号链接指向越界路径）。

**当前方案（自 2026-08 起）**：

```text
网关 ──sudo──▶ root 助手（仅做参数字符串校验）──runuser -u dsh-<name>──▶ 以用户身份执行实际文件操作
```

- `bin/dsh-file-{list,stat,read,put}` 在 root 下**仅校验参数形态**（`dsh-?*` 账号命名、禁止非法字符），然后 `runuser -u dsh-<name> -- <实际操作>`。
- 实际读写以目标用户自身身份执行，权限边界由 OS 强制：该用户无法读取他人 0700 目录，也无法访问 root 拥有的文件。
- 助手内保留 realpath 前缀校验，但其作用仅剩**保持退出码语义**（如越界拒绝 `exit=3`），不再是安全边界。
- 依赖 util-linux 的 `runuser`。

配套约束：

- `bin/` 目录必须保持 `root:root`，否则服务账号可替换助手脚本提权。
- sudoers 采用**固定路径白名单**（如 `/etc/sudoers.d/dsh-upload`），只放行 `dsh-file-put`、`dsh-file-stat`、`dsh-file-read`、`dsh-file-list` 四个助手，禁止 shell 通配。
- 网关对用户目录**零权限**：会话、历史、Key、文件都只能经由助手与实例访问。

## 4. 回环租户隔离（2026-08 新增）

DSH 实例把「Host 头是 127.0.0.1」当作特权请求的信任凭证（网关自己也是这么用的），但所有实例都监听在同一个 127.0.0.1 上，且每个租户的 agent 本就能执行任意 shell 命令——**文件系统隔离拦不住回环 HTTP**。没有回环防火墙时，租户 A 可以：

```bash
curl -H 'Host: 127.0.0.1:3102' http://127.0.0.1:3102/api/credentials.set ...
```

直接以「回环客户端」身份读写租户 B 实例的凭据、设置与会话。

防护（`bin/dsh-loopback-guard`，经 `units/dsh-loopback-guard.service` 开机应用、userctl 增删用户时即时刷新）：

```text
iptables OUTPUT 链 DSH_LOOPBACK_GUARD：
  ACCEPT  lo tcp uid=dsh-<name> dport=<自己端口>
  REJECT  lo tcp uid=dsh-<name> dport=<其他租户端口>   （逐目标端口，非按 uid 全量）
  REJECT  lo tcp uid=dsh-<name> dport=<网关端口>
  RETURN
```

要点：
- REJECT 必须按**目标端口**逐条下规则。按 uid 全量 REJECT 会把内核代表该用户实例发出的回包（sport=自己端口）一并掐断，表现为所有租户连接静默超时。
- root、网关服务账号与普通用户不受影响。
- 验证：`runuser -u dsh-admin -- curl http://127.0.0.1:3102/` 应被拒（tcp-reset），连 3101 正常。

## 5. 凭据与密钥

- 口令以 scrypt 哈希存储（兼容旧版 APR1），写入 `users.json`（原子写：临时文件 + rename）。
- 改密时 `pwdVer` 递增，已签发的会话令牌（内嵌 pwdVer）立即全部失效。
- API Key 仅存在于该用户私有目录的 `.credentials.yaml`（0600），网关不落库、不代理。
- 所有运行状态与密钥文件（`secret`、`users.json`、`state-cwd.json`、`.credentials.yaml`、`.local-run/`）均在 `.gitignore` 中，**严禁提交**。

## 6. 验证清单

在服务器上以 `<服务账号>` 执行（把 `<user>` 换成真实用户名）：

```bash
H=/opt/deepseek-harness/users/<user>

# 目录列表
sudo -n /opt/deepseek-harness/bin/dsh-file-list "$H" ''

# 写入 / 读取 / 统计（v2 长度协议：首行 "BYTES <n>" + 精确 n 字节；短流 exit=6 不落盘）
printf 'BYTES 6\nhello\n' | sudo -n /opt/deepseek-harness/bin/dsh-file-put "$H" "$H/workspace" t.txt
sudo -n /opt/deepseek-harness/bin/dsh-file-read  "$H" "$H/workspace/t.txt"   # 输出 hello
sudo -n /opt/deepseek-harness/bin/dsh-file-stat  "$H" "$H/workspace/t.txt"   # 输出 6

# 越界拒绝（应 exit=3）
sudo -n /opt/deepseek-harness/bin/dsh-file-read  "$H" /etc/passwd; echo "exit=$?"

# 降权生效：子进程应为 dsh-<user> 而非 root
ps -ef | grep -E 'runuser.*dsh-'

# 回环租户隔离（把端口换成另一租户的实例端口，应被拒绝）
runuser -u dsh-<user> -- curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}\n" http://127.0.0.1:<其他租户端口>/   # 期望 000
runuser -u dsh-<user> -- curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}\n" http://127.0.0.1:<自己端口>/       # 期望 200
```

若 `ps` 输出中文件操作子进程的用户是 `root`，说明助手未正确降权，**禁止上线**。

## 7. 运维注意

- 网关必须以专用账号 `dsh-gateway`（无 shell、sudo 仅限四个文件助手）运行；切勿用带 NOPASSWD 全量 sudo 的云镜像账号。
- **整棵安装树不得带 group/other 写位**（含 DSH monorepo 源码、`node_modules/`、`.agents/` 技能库——所有租户实例共享执行这份代码，可写点即跨租户注入点）。自检：`find /opt/deepseek-harness -not -path '*/users*' -perm /022 | wc -l` 必须为 0。
- `gateway/` 目录 `root:dsh-gateway 0770`（网关做 tmp+rename 原子写），目录内代码文件归 root:root 0644；`users.json`（0640）/`secret`（0600）属主为 `dsh-gateway`。
- 网关 systemd 单元不可设置 `NoNewPrivileges=yes`（会阻断 sudo 调 root 文件助手）。
- 不要给用户目录添加任何 ACL 读取授权--DSH 的 `assertOwnerOnly` 检查会拒绝实例启动（曾因此触发）。
- 自定义安装前缀时，必须同步修改 sudoers 白名单与网关的 `UPLOAD_HELPER` / `FILE_STAT_HELPER` / `FILE_READ_HELPER` / `FILE_LIST_HELPER` 四个环境变量；回环防护的网关端口经 `GW_PORT` 覆盖。
- 回环防护规则由 `dsh-loopback-guard.service` 开机应用，userctl 增删用户即时刷新；服务器上存在 docker/1Panel 等 nftables 使用方，规则以 iptables-nft 混合模式共存，勿手动 flush `filter` 表。
- 反向代理必须用 `proxy_set_header X-Forwarded-For $remote_addr;` **覆盖**客户端可能伪造的 XFF，否则网关 IP 限流可被绕过。
- 升级 DSH 后如需客户端行为修补（如 settings 持久化作用域），请自行评估，本仓库不修改 npm 包。