# DeepSeek Harness 多用户网关（dsh-multi-user-gateway）

为 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）Web 端增加**多用户门户**的零依赖 Node 网关：登录认证、每用户独立 DSH 实例与 OS 级数据隔离、每用户独立 API Key，以及内置的**交付文件抽屉**（下载 / 上传 / 当前工作区自动定位）。

## 特性

- **登录门户**：自研暗色登录页（漆面 + 金箔风格），scrypt 口令（兼容旧版 APR1）、HMAC 签名会话 Cookie（HttpOnly / Secure / SameSite=Lax）、登录限流（IP + 账号两级）、CSRF 双提交校验。
- **用户隔离**：每个用户一个独立 DSH 实例（独立端口），以独立系统账号 `dsh-<name>` 运行，`DSH_HOME` 指向其 0700 私有目录；`userctl.js` 一条命令完成建号 / 改密 / 删号 / 预置 Key。
- **每用户独立 API Key**：登录后无 Key 自动引导 `/setup` 填写，经回环 RPC 写入该用户私有的 `.credentials.yaml`（0600，属主仅本人）。
- **回环特权接口修复**：网关向后端呈现 `Host: 127.0.0.1:<port>` 并剥离浏览器信任标记，DSH 钉在回环的 settings / credentials / agentPreset 等特权接口在公网访问下同样可用。
- **交付文件抽屉**：主界面右下角两颗可拖动胶囊「交付文件」「上传文件」，白色抽屉内嵌文件浏览器——目录浏览、下载（attachment + 中文文件名）、多文件上传（100MB 上限）；自动定位到当前对话所在工作目录（嗅探会话 RPC 追踪 cwd，持久化恢复）。
- **安全边界**：所有用户文件访问经 sudoers 固定路径的 root 助手脚本（双重 realpath 边界校验）；网关进程对用户目录零权限；隐藏文件（含 `.credentials.yaml`）不可下载；SPA 注入尊重 `prefers-reduced-motion`、无玻璃拟态/渐变装饰。

## 架构

```
浏览器 ──https──▶ 反向代理(TLS, 例: OpenResty) ──▶ dsh-gateway(:3081) ──▶ 每用户 DSH 实例(:3101+)
                                  │                     │
                                  │ 会话/限流/CSRF/路由  │ 以独立 OS 账号 dsh-<name> 运行
                                  │ Key 引导/抽屉注入    │ DSH_HOME=<用户私有目录 0700>
                                  └──────────┬──────────┘
                                             └─ 文件访问走 sudo 助手: dsh-file-{list,stat,read,put}
```

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

4. 按 `nginx/dsh-https-1145.conf` 配置 TLS 反向代理（替换 `server_name` 为你的域名并挂证书）。
5. 登录后首次使用会引导填写 DeepSeek API Key（仅写入用户私有目录）。

> 环境变量：网关与 userctl 均支持 `USERS_FILE` / `SECRET_FILE` / `USERS_DIR` / `DEEPSEEK_BASE_URL` / `UPLOAD_MAX_MB` 等覆盖；userctl 还需 `DSH_TRUSTED_HOST`（实例 `--trusted-host`，示例默认 `127.0.0.1:1145`）。

## 交付文件抽屉的行为细节

- **自动定位**：网关嗅探代理流量中的 `session.history`（打开会话）与 `session.list`（每会话含 cwd），记住当前对话目录并持久化到 `state-cwd.json`；打开「交付文件」即列出该目录（目录失效自动回退工作区）。
- **嵌入与关闭**：抽屉以同源 iframe 内嵌（`X-Frame-Options: SAMEORIGIN`）；页面内「返回应用」运行时检测 iframe 环境，发 `postMessage('dshgw-close')` 关闭抽屉而非导航，杜绝嵌套打开。
- **上传**：原始字节体 `POST /__gw/upload?dir=&name=`，root 助手落盘并把属主转给 `dsh-<name>`（`chown --reference`），同名覆盖，超限 413。

## 安全注意事项

- `bin/` 目录必须保持 root:root 权限，否则服务账号可替换助手脚本提权。
- 用户凭据文件必须保持仅属主可读（0600）：DSH 启动时会强制检查（`assertOwnerOnly`）。本网关的 root 助手模型天然满足，不要给用户目录添加任何 ACL 读取授权（曾因此触发实例拒绝启动）。
- 网关与所有实例仅监听 127.0.0.1，公网只暴露 TLS 反代。
- 升级 DSH 后如需客户端行为修补（如 settings 持久化作用域），请自行评估，本仓库不修改 npm 包。

## License

[MIT](LICENSE)
