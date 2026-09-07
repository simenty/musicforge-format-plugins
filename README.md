# musicforge-format-plugins — MusicForge 本地格式迁移插件（L3）

MusicForge 主程序（[simenty/MusicForge](https://github.com/simenty/MusicForge)）的
**本地格式迁移插件仓**：独立版本、独立许可证（Apache-2.0）、**默认禁用 + 需显式确认（ACK 闸）**。

> 定位声明：本仓仅提供**用户合法持有文件的本地格式迁移/备份/解封装**能力。
> 不提供、也绝不宣称提供：在线获取加密音乐、批量平台下载、绕过会员或许可验证、
> 分享解密产物、资源索引/聚合、云端处理用户音频。平台 DRM 容器（grade D）**只识别
> 不处理**（`MF-FORMAT-DRM-UNSUPPORTED`）。

## 铁律（L3 唯一授权面）

1. `network = false` 强制——插件进程零网络（CI 断言）；
2. 读写被严格限制在 Host 授权的 `work_root` 内（canonical 化边界守卫，`..`/符号链接拒绝）；
3. **永不删除/移动/覆盖既有文件**：产物临时落盘 → magic + 音频属性双验 → 原子改名；
   目标存在即 `MF-OUTPUT-EXISTS`；
4. 校验失败产物进 `work_root/.musicforge/quarantine/<task>/`（隔离留痕，绝不静默删除）；
5. 源/产物 sha256 双哈希随行审计；Host 侧记入操作 Manifest，可还原。

## 插件与兼容性申报（PLUGIN_POLICY §4：逐格式声明）

| 插件 | 覆盖格式 | 状态 | 说明 |
|:--|:--|:--|:--|
| `kwm-migration` | `.kwm`（Kuwo，B 级申报） | **实验** | 自洽 roundtrip + 双验已测；与真实持有样本的互操作验证 pending |
| `qmc-legacy-migration` | `.qmc0/.qmc3/.qmcflac/.qmcogg/.tkm`（B 级） | 申报未发货 | 掩码常量待贡献/样本验证后落地 |
| `qmc2-ekey-migration` | `.mflac/.mgg`（C 级） | 申报未发货 | 需用户自备 ekey（本地传递）；不实现任何在线密钥获取（`network=false` 铁律） |

**「实验」状态的含义**：实现内部自洽性（roundtrip/校验/隔离）已被测试钉死，
但尚未经真实持有样本验证互操作。启用后请先对单个文件试迁移并试听确认。

## 安装与启用（待主仓 P6b ACK 闸接线后生效）

1. `cargo build --release`
2. 复制 `target/release/kwm-migration` + `plugins/kwm-migration/plugin.json`
   到白名单目录（`%LOCALAPPDATA%\MusicForge\plugins\kwm-migration\` 或
   `~/.local/share/musicforge/plugins/kwm-migration/`）
3. 主仓侧：`musicforge plugins acknowledge kwm-migration`（P6b 提供）——
   未确认调用返回 `MF-PLUGIN-ACK-REQUIRED`（码已注册）
4. 插件默认禁用；禁用/缺席时主程序五域功能 100% 可用（降级铁律）

## 契约

`format.migrate`（RFC：主仓 `docs/rfc/p6b-format-plugin-framework.md`）：
路径边界守卫 → 变换 → 临时落盘 → 双验 → 原子改名 → 审计行。
协议信封与 AI 域共用 X8 NDJSON（`musicforge-plugin-api`，path 依赖）。

## 开发

```bash
cargo build --release
cargo test        # 离线：路径守卫/覆盖拒绝/隔离区/roundtrip/协议分派
cargo clippy --all-targets -- -D warnings
```
