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
| `qmc-migration` | QMC 静态表系：`.qmc0/.qmc3/.qmcmp3/.bkcmp3`→mp3、`.qmcflac/.qmflac/.mflac/.bkcflac`→flac、`.qmc2/.qmcogg/.mgg`→ogg（B 级） | **实验** | 128 字节静态映射表 XOR（出处见审计表）；合成 fixture roundtrip + 双验已测；真实样本验证 pending |
| `qmc-migration`（同插件） | STag 尾标系：`.mflac0/.mflac1`→flac（C 级） | **实验（X49）** | QMCv2 流密码（RC4/Map 变体）+ **用户自备 ekey**（`options.ekey` 本地传递，零网络/无数据库/无 musicex API）；ekey 三态：缺失→`QMC-EKEY-REQUIRED` 引导、无效→`QMC-EKEY-INVALID`、有效→解封装直出 |
| `qmc-migration`（同插件） | QTag 尾标系：`.mgg0/.mgg1/.mggl`（C 级） | **D 级只识别报告** | 最末 4 字节 `QTag` 探测；内嵌 ekey 结构参考源未覆盖 → `QMC-VARIANT-QTAG-UNSUPPORTED` 显式拒绝（X49 维持） |

**probe 分流语义**（RFC-0002 §2.2）：宿主侧 `format.probe`（尾 4KB 采样）对静态表变体报
`requires_ekey=false`（可直接处理），对 STag/QTag 尾标变体报 `requires_ekey=true`——扫描报告
区分两类计数，用户一眼知道工作量。

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

## 参考项目与许可证审计表（RFC-0002 附录 B 常设要求）

> 新增参考项目必须**先登记许可证再阅读代码**。

| 项目 | 许可证 | 使用方式 | 登记日期 |
|:--|:--|:--|:--|
| jixunmoe/qmc-decode | **MIT** | QMC 静态表算法唯一参考源：`src/qmc_crypto.c` 的 128 字节映射表 + 索引公式（`i & 0x7F` / `i > 0x7FFF → (i % 0x7FFF) & 0x7F`）。`qmc.rs` 常量逐字节对照 | 2026-09-09 |
| **bczhc/qmc-dec**（Rust，未归档） | **Apache-2.0**（另有 LICENSE-MIT） | **X49：QMCv2 全链路参考源**——`src/lib.rs`（STag/QTag 尾标 = 最末 4 字节 magic）、`third_party/qmc2-rust/qmc2-crypto`（ekey 解析/TEA 派生/Map/RC4 变体 + 测试钉死值）。`qmc2v2.rs` 逐字移植 | 2026-09-09（X49） |
| **qmc2-rust**（qmc2-crypto crate，Jixun 系） | **MIT + Apache-2.0** 双许可 | 同上（子模块）；算法实现源头 | 2026-09-09（X49） |
| **tc_tea**（crates.io，0.1.4） | MIT | 腾讯 TEA 变体解密/加密（QQ TEA 16 轮 + 特殊 padding）——直接依赖，不 vendor | 2026-09-09（X49） |
| ix64/unlock-music | ~~MIT~~ | ⚠️ **已于 2022-11-08 因 QQ 音乐 DMCA 通知被 GitHub 下架**（dmca/2022-11/2022-11-04-qqmusic.md）。**禁止**从其 fork/镜像获取代码——RFC-0002 附录 A/B 制定时的参照地位作废 | 2026-09-09 |

### X48 裁决记录（2026-09-09，RFC-0002 执行时）

1. **参考系塌陷事实**：RFC-0002 附录 A 指定的 unlock-music（MIT 参照）已被 DMCA
   下架；qmc2-crypto（Rust 库）与 bczhc/qmc-decrypt 均不可达。仅
   jixunmoe/qmc-decode（C，MIT，归档存活）可用且仅覆盖**静态表**变体。
2. **STag/QTag 尾标变体裁决**：逐曲 ekey 与账户上下文绑定 = **账号绑定 DRM**。
   按 RFC-0002 §2.3 自身红线（「不处理账号绑定 DRM——D 级只识别报告」）+
   参考源缺位，落地为 **D 级识别报告**：probe 层 `requires_ekey=true` 分流 +
   migrate 层 `QMC-VARIANT-STAG-UNSUPPORTED` 显式拒绝。**不实现 ekey 派生/
   TEA 解密机制，绝不内置任何 ekey**（no bundled secrets）。
3. **静态表常量合规性**：128 字节映射表属「静态密钥表」范畴（RFC §2.3
   「永不内置密钥表**之外的**账户级机密」措辞内允许），且出处为 MIT 存活仓库。
   若未来收到平台方移除要求，将以运行时配置注入替代内置常量（预案）。
4. **验收映射**（RFC §5）：STag 尾探测 / ekey 分流拒绝 / 无内置 ekey grep /
   静态表 roundtrip——已由插件仓契约测试钉死；「正确 ekey → 解封装直出」一项
   随本裁决改为上述 D 级报告语义（等合法参考源与样本再评估）。

### X49 裁决记录（2026-09-09，主理人指示「启动执行 qmc 常量贡献」——解除暂缓）

1. **参考源重新核验（X48 前提修正）**：X48 依据 GitHub **API 搜索**得出
   「bczhc/qmc-decrypt 不可达」——后经 Web 搜索证伪：仓库实际名为
   **bczhc/qmc-dec**（重定向别名导致搜索漏报），未归档、2026-01 仍在推送。
   其 `third_party/qmc2-rust/qmc2-crypto`（MIT+Apache 双许可）含 QMCv2 全链路
   实现与**测试钉死数值**。
2. **法务分界确认**：「旧式内嵌 ekey 文件 + 用户自备 ekey 的**离线**解密」是
   qmc-dec / Kugo-Music-Converter 等存活开源项目的普遍形态（用户从自己客户端
   提取 ekey、本地传递）；越界方向 = musicex 新版（需平台 API 凭据）与
   ekey 数据库/在线获取——**红线不变：零网络、无数据库、不做 musicex**。
3. **落地范围**：STag（mflac0/mflac1）→ QMCv2 解密（RC4/Map 工厂分派，
   `qmc2v2.rs` 逐字移植 + 参考源测试值钉死）；QTag（mgg 系）内嵌 ekey 结构
   参考源未覆盖 → **维持 X48 的 D 级识别报告**。
4. **X48 验收第 4 项恢复**：「提供正确 ekey → 解封装直出」已达成
   （`qmc_stag_roundtrip_with_valid_ekey`，真实 ekey fixture）。
5. **CI 断言语义更新**：no-bundled-ekeys 断言保留「无 ekey 数据库（64+ hex
   常量）」；原「ekey 派生实现禁入」改为「**网络栈禁入**」（reqwest/ureq/hyper
   依赖即失败）——ekey 派生本身已合法落地，风险面收敛到「在线获取」。
6. **风险敞口如实记录**：unlock-music DMCA 案例表明平台方对此类工具有执法
   历史；本项目延续「独立分发、默认禁用、ACK 闸、实验状态申报、真实样本
   验证 pending」的既有缓释措施。主理人知情决策。
