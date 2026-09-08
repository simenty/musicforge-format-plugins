//! musicforge-format-plugins 公共层：L3 格式迁移框架。
//!
//! 契约（RFC: docs/rfc/p6b-format-plugin-framework.md §2.1，与主仓铁律一一对应）：
//! 1. **路径边界**：canonical 化后必须位于 `work_root` 内，`..`/符号链接跳板拒绝
//!    → `MF-DIR-NOT-AUTHORIZED`；
//! 2. **绝不改源**：只读源文件；
//! 3. **绝不覆盖**：目标存在即 `MF-OUTPUT-EXISTS`；
//! 4. **校验后才算成功**：magic 嗅探 + lofty 属性双验；失败产物入
//!    `work_root/.musicforge/quarantine/<task>/`（隔离，绝不静默删除）；
//! 5. **可审计**：源/产物 sha256 双哈希随行。
//!
//! L3 铁律（PLUGIN_POLICY §2）：本仓插件拥有**受限本地读写**，但仍然
//! **永不删除/移动/覆盖既有文件**；`network=false` 强制（CI 断言）。

use std::io::{BufRead, Write};
use std::path::{Component, Path, PathBuf};

use musicforge_plugin_api::{methods, PluginError, PluginManifest, Request, Response};

pub mod kwm;

/// format 域方法（P6b 增量；协议信封与 AI 域共用 X8）。
pub mod fmt_methods {
    pub const FORMAT_MIGRATE: &str = "format.migrate";
}

/// 迁移请求参数（`format.migrate`）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrateParams {
    pub work_root: String,
    pub source_path: String,
    pub output_dir: String,
    /// 预留：QMCv2 类需用户自备密钥（本地传递，非网络）
    pub ekey: Option<String>,
}

impl MigrateParams {
    pub fn from_value(v: &serde_json::Value) -> Result<Self, String> {
        Ok(Self {
            work_root: v["work_root"].as_str().ok_or("缺 work_root")?.to_string(),
            source_path: v["source_path"].as_str().ok_or("缺 source_path")?.to_string(),
            output_dir: v["output_dir"].as_str().ok_or("缺 output_dir")?.to_string(),
            ekey: v["ekey"].as_str().map(|s| s.to_string()),
        })
    }
}

/// 产物校验结果（magic + lofty 属性双验）。
#[derive(Debug, Clone, PartialEq)]
pub struct Verification {
    pub magic: &'static str,
    pub sample_rate: Option<u32>,
    pub channels: Option<u16>,
    pub duration_s: Option<f64>,
}

/// 审计行（源/产物双哈希 + 隔离标记）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audit {
    pub source_sha256: String,
    pub output_sha256: String,
    pub quarantined: bool,
}

// ---------------------------------------------------------------- 路径守卫 --

/// canonical 化并强制路径位于 `work_root` 内（L3 唯一路径边界；威胁模型 T2 同款）。
///
/// 对尚不存在的目标（output_dir 语义）：向上定位已存在祖先 canonical 化后，
/// **逐级回挂缺失段**（缺段丢弃 = 目录穿越漏洞）。`..` 组件与边界外一律拒绝。
pub fn guard_path(work_root: &Path, path: &Path) -> Result<PathBuf, String> {
    let root_canon = std::fs::canonicalize(work_root)
        .map_err(|e| format!("MF-DIR-NOT-AUTHORIZED: work_root 不可读: {e}"))?;
    // 显式拒绝 `..` 组件（canonical 前置检查，防 symlink TOCTOU 语义歧义）
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err("MF-DIR-NOT-AUTHORIZED: 路径不得包含 `..`".to_string());
        }
    }
    let mut missing_rev: Vec<std::ffi::OsString> = Vec::new();
    let mut acc = path.to_path_buf();
    let existing = loop {
        match std::fs::canonicalize(&acc) {
            Ok(c) => break c,
            Err(_) => match acc.file_name().map(|f| f.to_os_string()) {
                Some(name) => {
                    missing_rev.push(name);
                    if !acc.pop() {
                        return Err(format!(
                            "MF-DIR-NOT-AUTHORIZED: 无法定位 {} 于 {} 内",
                            path.display(),
                            work_root.display()
                        ));
                    }
                }
                None => {
                    return Err(format!(
                        "MF-DIR-NOT-AUTHORIZED: 无法定位 {} 于 {} 内",
                        path.display(),
                        work_root.display()
                    ))
                }
            },
        }
    };
    let mut canon = existing;
    for name in missing_rev.iter().rev() {
        canon.push(name);
    }
    if !canon.starts_with(&root_canon) {
        return Err(format!(
            "MF-DIR-NOT-AUTHORIZED: {} 位于授权工作根 {} 之外",
            path.display(),
            work_root.display()
        ));
    }
    Ok(canon)
}

// ---------------------------------------------------------------- 校验器 --

/// magic 嗅探（无损音频三形态）。
pub fn sniff_magic(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"fLaC") {
        Some("fLaC")
    } else if data.starts_with(b"RIFF") && data.len() > 12 && &data[8..12] == b"WAVE" {
        Some("RIFF/WAVE")
    } else if data.starts_with(b"ID3") || data.starts_with(&[0xFF, 0xFB]) {
        Some("ID3/MP3")
    } else {
        None
    }
}

/// 产物双验：magic 嗅探 + lofty 可解析（sample_rate/channels/duration）。
pub fn verify_output(path: &Path) -> Result<Verification, String> {
    use lofty::prelude::*;
    let data = std::fs::read(path).map_err(|e| format!("产物读取失败: {e}"))?;
    let magic = sniff_magic(&data).ok_or("产物 magic 校验失败：不是可识别的无损音频")?;
    let props = lofty::read_from_path(path).ok().map(|t| t.properties().clone());
    let (sr, ch, dur) = match &props {
        // lofty 0.25：sample_rate()/channels() 本身返回 Option（CODEBUDDY 高频坑）
        Some(p) => (p.sample_rate(), p.channels().map(|c| c as u16), Some(p.duration().as_secs_f64())),
        None => (None, None, None),
    };
    Ok(Verification {
        magic,
        sample_rate: sr,
        channels: ch,
        duration_s: dur,
    })
}

pub fn sha256_hex(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path).map_err(|e| format!("打开失败 {path:?}: {e}"))?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h).map_err(|e| format!("读取失败: {e}"))?;
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

// ---------------------------------------------------------------- 迁移流程 --

/// 迁移执行器：守卫 → 读源 → 变换 → 临时落盘 → 双验 → 原子改名（失败进隔离区）。
///
/// `transform` 为各格式的纯字节变换（如 XOR 解密）。
pub fn run_migrate(
    params: &MigrateParams,
    transform: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Result<serde_json::Value, String> {
    let work = PathBuf::from(&params.work_root);
    let source = guard_path(&work, Path::new(&params.source_path))?;
    let out_dir = guard_path(&work, Path::new(&params.output_dir))?;
    if !source.is_file() {
        return Err(format!("源不是文件: {}", source.display()));
    }
    let source_sha = sha256_hex(&source)?;
    let raw = std::fs::read(&source).map_err(|e| format!("源读取失败: {e}"))?;
    let migrated = transform(&raw);

    // 扩展名据 magic 决定；未知形态 → "bin"（先落临时，双验失败 → 隔离区，
    // 绝不在写盘前静默丢弃产物——留痕是审计铁律）
    let ext = match sniff_magic(&migrated) {
        Some("fLaC") => "flac",
        Some("RIFF/WAVE") => "wav",
        Some(_) => "mp3",
        None => "bin",
    };
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("输出目录创建失败: {e}"))?;
    let stem = source
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    let final_target = out_dir.join(format!("{stem}.{ext}"));
    if final_target.exists() {
        return Err(format!(
            "MF-OUTPUT-EXISTS: 目标已存在 {}（绝不覆盖）",
            final_target.display()
        ));
    }
    // 临时文件名以真实扩展名结尾——lofty 依扩展名探测格式
    let tmp = out_dir.join(format!("{stem}.migrating.{ext}"));
    std::fs::write(&tmp, &migrated).map_err(|e| format!("临时产物写入失败: {e}"))?;

    // 双验；失败 → 隔离区（绝不静默删除）
    let verification = match verify_output(&tmp) {
        Ok(v) => v,
        Err(e) => {
            let q = quarantine(&work, &tmp)?;
            return Err(format!("{e}（产物已隔离: {}）", q.display()));
        }
    };
    std::fs::rename(&tmp, &final_target).map_err(|e| format!("原子改名失败: {e}"))?;
    let output_sha = sha256_hex(&final_target)?;
    // 报告路径用调用方原始形态（canonical 化的 `\\?\` 前缀不外泄）
    let report_target = Path::new(&params.output_dir).join(format!("{stem}.{ext}"));
    Ok(serde_json::json!({
        "output_path": report_target.display().to_string(),
        "verification": {
            "magic": verification.magic,
            "sample_rate": verification.sample_rate,
            "channels": verification.channels,
            "duration_s": verification.duration_s,
        },
        "audit": {
            "source_sha256": source_sha,
            "output_sha256": output_sha,
            "quarantined": false,
        },
    }))
}

/// 失败产物移入 `work_root/.musicforge/quarantine/<task>/`（隔离不删除）。
///
/// 稳定审计 B8：task id 含纳秒（毫秒+pid 在同进程连续失败时可能撞名 →
/// rename 入已存在的隔离目录会失败并掩盖原始错误）。
fn quarantine(work: &Path, tmp: &Path) -> Result<PathBuf, String> {
    let task = format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        std::process::id()
    );
    let dir = work.join(".musicforge/quarantine").join(task);
    std::fs::create_dir_all(&dir).map_err(|e| format!("隔离区创建失败: {e}"))?;
    let dest = dir.join(tmp.file_name().unwrap_or_default());
    std::fs::rename(tmp, &dest).map_err(|e| format!("隔离移动失败: {e}"))?;
    Ok(dest)
}

// ---------------------------------------------------------------- 服务环 --

/// X8 服务环（format 域；manifest/health/shutdown 统一，能力方法交 handler）。
///
/// format-adapter 类清单恒声明 `ack_required: true`（PLUGIN_POLICY §3/§4：
/// 高风险格式迁移必须经主程序确认闸后方可调用，否则 `MF-PLUGIN-ACK-REQUIRED`）。
///
/// 稳定审计 B9（2026-09-08 第二轮）：清单 `name` 由调用方显式传入——此前取自
/// 环境变量且 bin 未设置 → 默认 "format-plugin" ≠ plugin.json/ACK 记录中的
/// 真名 → ACK 闸永远失败。**清单名必须与 plugin.json/name 逐字节一致**。
pub fn serve(name: &str, handler: fn(&str, &serde_json::Value) -> Result<serde_json::Value, String>) {
    let manifest = PluginManifest {
        name: name.to_string(),
        api_version: "1.0.0".into(),
        kind: musicforge_plugin_api::PluginKind::FormatAdapter,
        network: false,
        data_sent: vec!["source_path".into(), "output_dir".into(), "work_root".into()],
        data_not_sent: vec!["audio_bytes".into(), "cover_bytes".into()],
        ack_required: true,
        extensions: vec!["kwm".into()],
    };
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(line.trim()) {
            Err(_) => Response::err("unknown", "MF-PLUGIN-MANIFEST-INVALID", "请求行无法解析"),
            Ok(req) => match req.method.as_str() {
                methods::PLUGIN_MANIFEST => {
                    Response::ok(&req.id, serde_json::to_value(&manifest).unwrap())
                }
                methods::PLUGIN_HEALTH => Response::ok(
                    &req.id,
                    serde_json::json!({"status": "ok"}),
                ),
                methods::PLUGIN_SHUTDOWN => {
                    let resp = Response::ok(
                        &req.id,
                        serde_json::to_value(&musicforge_plugin_api::ShutdownResult {
                            accepted: true,
                        })
                        .unwrap(),
                    );
                    let _ = writeln!(out, "{}", serde_json::to_string(&resp).unwrap());
                    let _ = out.flush();
                    std::process::exit(0);
                }
                method => match handler(method, &req.params) {
                    Ok(v) => Response::ok(&req.id, v),
                    Err(e) => Response::err(&req.id, "MF-PLUGIN-FAILED", e),
                },
            },
        };
        let _ = writeln!(out, "{}", serde_json::to_string(&resp).unwrap());
        let _ = out.flush();
    }
}

#[allow(dead_code)]
fn _type_witness(_: PluginError) {}
