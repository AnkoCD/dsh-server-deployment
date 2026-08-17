# 各 Issue 回复草稿

可直接粘贴到 <https://github.com/AnkoCD/dsh-server-deployment/issues> 的回复。发布前请核对实际提交内容与日期。

---

## Issue #1 · dsh-file-\* root 助手 TOCTOU 竞态

> 已修复，感谢报告与建议方案。
>
> 按你推荐的方案 1 落实：`bin/dsh-file-{put,read,stat,list}` 现在**不再以 root 执行任何文件操作**——root 只做参数（字符串）校验与身份推导（从 home basename 得到 `dsh-<name>`，且严格校验 `dsh-[a-z0-9][a-z0-9_-]*`，杜绝被引导执行到 root 或其它系统账号），随后经 `runuser -u dsh-<name> --` 降权，所有 mktemp/cat/stat/mv 都以该用户自身身份发生：
>
> - 上传（put）：临时文件 + 大小上限检查 + 改名，全程在用户身份下完成，`chown --reference` 已随之消除（产物天然属主为本人）。
> - 读/stat/列目录（read/stat/list）：同样降权执行。
> - realpath 前缀校验保留，但仅为稳定退出码语义（2/3/4/5 → HTTP 400/403/404/413），不再是安全边界。
>
> 影响面：sudoers 形态不变（仍是 4 个固定路径 root:root 脚本）；`gateway/server.js` 与 users.json 零改动。README「安全注意事项」已同步，并附 Linux 验证清单（含 `ps -ef | grep runuser` 确认子进程属主）。
>
> 唯一新增依赖：util-linux 的 `runuser`（Ubuntu 自带）。

## Issue #2 · 多用户登录与数据隔离

> 支持，详见新增文档 [docs/multi-user-isolation.md](docs/multi-user-isolation.md)（已挂到 README）。
>
> 一句话：每个用户一个独立 DSH 实例（独立端口 3101+）+ 独立系统账号 `dsh-<name>` + 0700 私有目录（DSH_HOME）——认证、进程、文件系统、凭据（.credentials.yaml 0600）、API Key、交付文件全部逐用户隔离；不隔离的是主机级资源与共享的 DSH 安装包，root 管理员仍可管理一切。另请注意：交付文件的文件助手已因 issue #1 改为以用户自身身份执行，竞态不再构成跨用户越权。

## Issue #3 · 可自定义路径

> 已落实，感谢建议。改动：
>
> 1. `gateway/userctl.js` 新增 `DSH_BASE_DIR`（默认 `/opt/deepseek-harness`），并开放 `DSH_USERS_DIR` / `DSH_USERS_FILE` / `DSH_SETTINGS_SRC` / `DSH_NODE_BIN` / `DSH_DSH_BIN` 细粒度覆盖。
> 2. `bin/dsh-users.sh` 与 `bin/dsh-file-list` 改为**脚本自定位**：从自身位置解析仓库根与 node（缺失时回退 PATH），任意前缀或 git 检出目录可直接运行。
> 3. `units/dsh-gateway.service` 增加 `EnvironmentFile=-/etc/default/dsh-gateway`（可用环境文件覆盖，无需改 unit），并在注释中给出自定义前缀的一行 `sed` 生成命令。
> 4. README 新增完整环境变量表格；注意自定义前缀时需同步修改 sudoers 与网关的 `UPLOAD_HELPER` / `FILE_STAT_HELPER` / `FILE_READ_HELPER` / `FILE_LIST_HELPER` 四个变量。
>
> 网关 `gateway/server.js` 原有的 `USERS_FILE` / `SECRET_FILE` / `USERS_DIR` 等环境变量覆盖保持不变。