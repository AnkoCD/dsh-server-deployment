# DeepSeek Harness 服务器部署（dsh-server-deployment）

<p align="center">
  <img src="assets/cover.png" alt="DSH 服务器部署封面" width="100%">
</p>

为 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）Web 端增加**多用户门户**的零依赖 Node 网关：登录认证、每用户独立 DSH 实例与 OS 级数据隔离、每用户独立 API Key，以及内置的**交付文件抽屉**（下载 / 上传 / 当前工作区自动定位）。隔离以 **OS 账号为边界**而非网关代码——文件访问经 sudo 助手 `runuser` 降权为 `dsh-<name>` 用户执行（修复 issue #1 TOCTOU 竞态），网关对用户目录零权限；完整机制见 [docs/multi-user-isolation.md](docs/multi-user-isolation.md)。

> **部署定位（重要）**：本项目是**服务器端部署**方案——网关、每用户 DSH 实例与文件助手全部运行在**远程服务器**上，多个用户通过浏览器（公网域名 + HTTPS）访问各自的会话与交付文件；它**不是本机 / 桌面工具**，**无需在用户电脑上安装任何软件**。文档中的示例路径（如 `/opt/deepseek-harness`、`/etc/systemd/system`）均为服务器端路径。

## 特性

- **登录门户**：自研暗色登录页（漆面 + 金箔风格），scrypt 口令（兼容旧版 APR1）、HMAC 签名会话 Cookie（HttpOnly / Secure / SameSite=Lax）、登录限流（IP + 账号两级）、CSRF 双提交校验。
- **用户隔离**：每个用户一个独立 DSH 实例（独立端口），以独立系统账号 `dsh-<name>` 运行，`DSH_HOME` 指向其 0700 私有目录；`userctl.js` 一条命令完成建号 / 改密 / 删号 / 预置 Key。
- **每用户独立 API Key**：登录后无 Key 自动引导 `/setup` 填写，经回环 RPC 写入该用户私有的 `.credentials.yaml`（0600，属主仅本人）。
- **回环特权接口修复**：网关向后端呈现 `Host: 127.0.0.1:<port>` 并剥离浏览器信任标记，DSH 钉在回环的 settings / credentials / agentPreset 等特权接口在公网访问下同样可用。
- **交付文件抽屉（文件管理）**：主界面右下角**一颗**可拖动胶囊「🗂 文件管理」（2026-08 起由「交付文件」+「上传文件」双胶囊合并而来），白色抽屉内嵌文件浏览器——目录浏览、下载（attachment + 中文文件名）、多文件上传（100MB 上限）；自动定位到当前对话所在工作目录（嗅探会话 RPC 追踪 cwd，持久化恢复）。胶囊在 SPA 弹窗（设置面板/模态）打开时自动隐藏，避免遮挡。
- **安全边界**：所有用户文件访问经 sudoers 固定路径的助手脚本——root 仅校验参数并降权，文件操作以 `dsh-<name>` 用户自身身份执行（修复 issue #1 的 TOCTOU 竞态）；网关进程对用户目录零权限；隐藏文件（含 `.credentials.yaml`）不可下载；SPA 注入尊重 `prefers-reduced-motion`、无玻璃拟态/渐变装饰。

## 架构

```
浏览器 ──https──▶ 反向代理(TLS, 例: OpenResty) ──▶ dsh-gateway(:3100) ──▶ 每用户 DSH 实例(:3101+)
                                  │                     │
                                  │ 会话/限流/CSRF/路由  │ 以独立 OS 账号 dsh-<name> 运行
                                  │ Key 引导/抽屉注入    │ DSH_HOME=<用户私有目录 0700>
                                  └──────────┬──────────┘
                                             └─ 文件访问走 sudo 助手: dsh-file-{list,stat,read,put}
```

> 网关默认端口在运行部署中为 **3100**（本仓库示例为 3081，可用环境变量 `PORT` 覆盖）；每用户实例
> 自 3101 递增，由 `userctl` 分配。

多用户与数据隔离的完整说明见 [docs/multi-user-isolation.md](docs/multi-user-isolation.md)。

## 目录结构

```
gateway/                # 网关本体（零依赖 Node）
  server.js             #   登录/会话/限流/CSRF/反代/SPA注入/文件抽屉/上传下载接口
  auth.js               #   scrypt + APR1 口令校验
  credentials.js        #   .credentials.yaml 读写（仅 userctl 使用）
  userctl.js            #   用户管理：OS 账号/端口/实例/Key
  _smoke.js             #   网关冒烟测试（本地即可运行，无需 DSH）
  static/               #   登录前可访问的静态资源（manifest/favicon）
bin/                    # 主机端入口与 root 助手
  dsh-users.sh          #   userctl 的 sudo 入口
  dsh-file-{list,stat,read,put}[.js]
units/                  # systemd 单元模板（网关 + 每用户实例由 userctl 生成）
nginx/                  # TLS 反向代理示例配置（已占位化域名）
```

## 快速部署（概览）

1. 安装 DSH（npm 包）并准备 Node 运行时；按 `units/` 配置网关 systemd 服务（`User=<服务账号>`，仅监听 127.0.0.1）。
2. 用 `sudo bin/dsh-users.sh add <用户>` 建号（自动创建 OS 账号、分配端口、生成并启动实例）。
3. 安装 root 助手并配置 sudoers（固定路径白名单）：

   ```bash
   install -o root -g root -m 0755 bin/dsh-file-* /opt/deepseek-harness/bin/
   # /etc/sudoers.d/dsh-upload:
   # <服务账号> ALL=(root) NOPASSWD: /opt/deepseek-harness/bin/dsh-file-put, /opt/deepseek-harness/bin/dsh-file-stat, /opt/deepseek-harness/bin/dsh-file-read, /opt/deepseek-harness/bin/dsh-file-list
   ```

   升级或自检时可在服务器上按以下清单验证助手（把 `<user>` 换成真实用户名）：

   ```bash
   H=/opt/deepseek-harness/users/<user>
   sudo -n /opt/deepseek-harness/bin/dsh-file-list "$H" ''          # JSON 目录列表
   echo hello | sudo -n /opt/deepseek-harness/bin/dsh-file-put "$H" "$H/workspace" t.txt
   sudo -n /opt/deepseek-harness/bin/dsh-file-stat  "$H" "$H/workspace/t.txt"   # 输出 6
   sudo -n /opt/deepseek-harness/bin/dsh-file-read  "$H" "$H/workspace/t.txt"   # 输出 hello
   sudo -n /opt/deepseek-harness/bin/dsh-file-read  "$H" /etc/passwd; echo "exit=$?"  # exit=3（越界拒绝）
   ps -ef | grep -E 'runuser.*dsh-'                                  # 子进程应为 dsh-<user> 而非 root
   ```

4. 按 `nginx/dsh-https-1145.conf` 配置 TLS 反向代理（替换 `server_name` 为你的域名并挂证书）。
5. 登录后首次使用会引导填写 DeepSeek API Key（仅写入用户私有目录）。

> 环境变量：网关与 userctl 均可用环境变量覆盖默认的 `/opt/deepseek-harness` 路径：

| 变量 | 作用方 | 默认 |
|---|---|---|
| `DSH_BASE_DIR` | userctl / dsh-users.sh 派生路径的安装前缀 | `/opt/deepseek-harness` |
| `DSH_USERS_DIR`、`DSH_USERS_FILE`、`DSH_SETTINGS_SRC`、`DSH_NODE_BIN`、`DSH_DSH_BIN` | userctl 细粒度覆盖 | 由 BASE_DIR 派生 |
| `USERS_FILE`、`SECRET_FILE`、`USERS_DIR` | 网关 | `/opt/deepseek-harness/...` |
| `UPLOAD_HELPER`、`FILE_STAT_HELPER`、`FILE_READ_HELPER`、`FILE_LIST_HELPER` | 网关调用助手的绝对路径 | `/opt/deepseek-harness/bin/dsh-file-*`（**自定义前缀时必须同步改 sudoers 与这四个变量**） |
| `HOST`、`PORT`、`SESSION_TTL`、`COOKIE_SECURE`、`DEEPSEEK_BASE_URL`、`UPLOAD_MAX_MB`、`MAX_IP_ATTEMPTS`、`MAX_USER_ATTEMPTS`、`WINDOW_MS`、`LOCK_MS` | 网关 | 见 `gateway/server.js` |
| `DSH_TRUSTED_HOST` | userctl（实例 `--trusted-host`） | `127.0.0.1:1145` |

`bin/dsh-users.sh` 与 `bin/dsh-file-list` 已按自身位置自定位：任意目录检出即可直接运行（`dsh-users.sh` 首次调用自动重提权为 root；node 解析相对脚本位置，缺失时回退 `PATH`）。自定义安装前缀时 systemd 单元用上面的 `sed` 命令生成；网关 systemd 单元还支持 `EnvironmentFile=-/etc/default/dsh-gateway`，可在该文件里统一注入上述环境变量。

## 交付文件抽屉的行为细节

- **自动定位**：网关嗅探代理流量中的 `session.history`（打开会话）与 `session.list`（每会话含 cwd），记住当前对话目录并持久化到 `state-cwd.json`；打开「文件管理」即列出该目录（目录失效自动回退工作区）。
- **嵌入与关闭**：抽屉以同源 iframe 内嵌（`X-Frame-Options: SAMEORIGIN`）；页面内「返回应用」运行时检测 iframe 环境，发 `postMessage('dshgw-close')` 关闭抽屉而非导航，杜绝嵌套打开。
- **上传**：原始字节体 `POST /__gw/upload?dir=&name=`，助手降权为 `dsh-<name>` 落盘（root 仅校验参数），文件属主天然为本人，同名覆盖，超限 413。

## 安全注意事项

- `bin/` 目录必须保持 root:root 权限，否则服务账号可替换助手脚本提权。
- 文件助手（dsh-file-put/read/stat/list）自 2026-08 起 root 仅做参数字符串校验与身份切换，所有文件操作经 `runuser -u dsh-<name>` 以用户自身身份执行（修复 issue #1 的 TOCTOU 竞态）；助手内的 realpath 前缀校验仅保留退出码语义，不再是安全边界。依赖 util-linux 的 `runuser`。
- 用户凭据文件必须保持仅属主可读（0600）：DSH 启动时会强制检查（`assertOwnerOnly`）。本网关的 root 助手模型天然满足，不要给用户目录添加任何 ACL 读取授权（曾因此触发实例拒绝启动）。
- 网关与所有实例仅监听 127.0.0.1，公网只暴露 TLS 反代。
- 升级 DSH 后如需客户端行为修补（如 settings 持久化作用域），请自行评估，本仓库不修改 npm 包。
- 使用时微软的密码自动填充会给左侧工作区目录带来问题，尽量关闭自动填充。

## License

[MIT](LICENSE)
