//! `qmc-migration`（QQ 音乐 QMC 系，RFC-0002 / X48 裁决）。
//!
//! **变体分级**（RFC-0002 附录 D + §2.3 法务红线）：
//! - **静态表变体**（qmc0/qmc3/qmcflac/qmc2/qmcogg/bkc*/qm* 旧形态）：
//!   逐字节 XOR 一个 128 字节静态映射表——**开箱即用基本盘**（R25 对策）。
//!   算法出处：jixunmoe/qmc-decode（MIT，归档存活仓；README 审计表已登记）。
//! - **尾标变体**（mflac0/mflac1/mgg0/mgg1/mggl 等，文件尾 `STag`/`QTag` 标记）：
//!   逐曲 ekey = **账号绑定 DRM** → 按 RFC-0002 §2.3 走 D 级「识别报告」：
//!   probe 层报 `requires_ekey=true`；migrate 层显式拒绝
//!   （`QMC-VARIANT-STAG-UNSUPPORTED`，X42 双层错误模型透传业务码）。
//!   绝不解密、绝不内置 ekey 派生机制（no bundled secrets；参考源亦已消亡：
//!   unlock-music 于 2022-11 被 DMCA 下架——详见插件仓 README 审计表）。
//!
//! **兼容性申报**（PLUGIN_POLICY §4）：静态表变体以合成 fixture 自洽 roundtrip
//! 钉死（加密端 = 解密端同表镜像）；与真实持有样本的互操作验证 pending——
//! 未经样本验证前按「实验」状态申报。仅处理用户合法持有的本地文件；
//! 永不联网、永不改源。

use std::path::Path;

/// QMC 静态映射表（128 字节）。
///
/// 出处：jixunmoe/qmc-decode `src/qmc_crypto.c` `privKey[128]`（MIT，2021 归档）。
/// 等价于基础 256 字节表按 `(offset² + 27) & 0xFF` 索引的预展开优化形态。
/// 该表为 QQ 音乐旧版静态加密的公开社区事实常量——按 RFC-0002 §2.3，
/// 「密钥表之外的账户级机密」永不内置；本表属静态密钥表范畴（社区共识立场）。
pub const QMC_MAP: [u8; 128] = [
    0xc3, 0x4a, 0xd6, 0xca, 0x90, 0x67, 0xf7, 0x52, 0xd8, 0xa1, 0x66, 0x62, 0x9f, 0x5b, 0x09,
    0x00, //
    0xc3, 0x5e, 0x95, 0x23, 0x9f, 0x13, 0x11, 0x7e, 0xd8, 0x92, 0x3f, 0xbc, 0x90, 0xbb, 0x74,
    0x0e, //
    0xc3, 0x47, 0x74, 0x3d, 0x90, 0xaa, 0x3f, 0x51, 0xd8, 0xf4, 0x11, 0x84, 0x9f, 0xde, 0x95,
    0x1d, //
    0xc3, 0xc6, 0x09, 0xd5, 0x9f, 0xfa, 0x66, 0xf9, 0xd8, 0xf0, 0xf7, 0xa0, 0x90, 0xa1, 0xd6,
    0xf3, //
    0xc3, 0xf3, 0xd6, 0xa1, 0x90, 0xa0, 0xf7, 0xf0, 0xd8, 0xf9, 0x66, 0xfa, 0x9f, 0xd5, 0x09,
    0xc6, //
    0xc3, 0x1d, 0x95, 0xde, 0x9f, 0x84, 0x11, 0xf4, 0xd8, 0x51, 0x3f, 0xaa, 0x90, 0x3d, 0x74,
    0x47, //
    0xc3, 0x0e, 0x74, 0xbb, 0x90, 0xbc, 0x3f, 0x92, 0xd8, 0x7e, 0x11, 0x13, 0x9f, 0x23, 0x95,
    0x5e, //
    0xc3, 0x00, 0x09, 0x5b, 0x9f, 0x62, 0x66, 0xa1, 0xd8, 0x52, 0xf7, 0x67, 0x90, 0xca, 0xd6, 0x4a,
];

/// 静态表密钥流字节（偏移 `i` 处；与 C 参考实现逐字节一致）。
pub fn encode_key(i: usize) -> u8 {
    QMC_MAP[if i > 0x7FFF {
        (i % 0x7FFF) & 0x7F
    } else {
        i & 0x7F
    }]
}

/// 静态表变体逐字节 XOR（XOR 自逆：同一函数即解密亦为加密端 fixture 构造）。
pub fn qmc_map_transform(raw: &[u8]) -> Vec<u8> {
    raw.iter()
        .enumerate()
        .map(|(i, b)| b ^ encode_key(i))
        .collect()
}

// ---------------------------------------------------------------- 变体识别 --

/// QMC 变体分类（probe 识别表 = RFC-0002 附录 D 静态部分 + 尾标探测优先）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QmcVariant {
    /// 静态表变体：可直接迁移；`out_ext` 为预期产物扩展名。
    StaticMap { out_ext: &'static str },
    /// `STag` 尾标（mflac 系）：逐曲 ekey（账号绑定 DRM）——识别报告，不迁移。
    StagTail,
    /// `QTag` 尾标（mgg 系）：同上。
    QtagTail,
    /// 非本插件能力范围。
    Unknown,
}

/// 扩展名 → 静态表变体映射（RFC-0002 附录 D：「否（静态表）」各行；
/// `mflac`/`mgg` 无数字形态按规格归静态表——尾标探测优先保证
/// 同名扩展带 STag/QTag 尾时仍走 ekey 分流）。
fn static_ext_map(ext_lower: &str) -> Option<&'static str> {
    Some(match ext_lower {
        "qmc0" | "qmc3" | "qmcmp3" | "bkcmp3" => "mp3",
        "qmcflac" | "qmflac" | "mflac" | "bkcflac" => "flac",
        "qmc2" | "qmcogg" | "mgg" => "ogg",
        _ => return None,
    })
}

/// 变体识别：**尾标探测优先**（字节事实 > 扩展名申报）——
/// 同名扩展（如 `mflac`）在旧形态下是静态表、在尾标形态下是 ekey 变体。
///
/// `tail` 为文件尾部采样（建议 ≥ 256B；空/过短按无尾标处理）。
pub fn classify(file_name: &str, tail: &[u8]) -> QmcVariant {
    // 尾标 magic 扫描：STag/QTag 结构以 4 字节 magic 开头且位于文件尾部。
    if find_tail_magic(tail, b"STag") {
        return QmcVariant::StagTail;
    }
    if find_tail_magic(tail, b"QTag") {
        return QmcVariant::QtagTail;
    }
    let ext = Path::new(file_name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    match static_ext_map(&ext) {
        Some(out_ext) => QmcVariant::StaticMap { out_ext },
        // 尾标系扩展名（无尾标实测）——按扩展名申报为尾标变体家族；
        // 产物双验兜底（真实旧形态静态表文件会被识别为可迁移吗？不会：
        // 保守声明为需人工确认，避免误报「可直接处理」后迁移失败）
        _ if matches!(ext.as_str(), "mflac0" | "mflac1" | "mgg0" | "mgg1" | "mggl") => {
            QmcVariant::StagTail
        }
        _ => QmcVariant::Unknown,
    }
}

/// 尾部采样中查找尾标 magic（只在最后 64 字节窗口内——STag/QTag 结构
/// 固定驻留文件末尾，窗口过大会把音频流中的偶然 4 字节序列误判）。
fn find_tail_magic(tail: &[u8], magic: &[u8; 4]) -> bool {
    let start = tail.len().saturating_sub(64);
    tail[start..].windows(4).any(|w| w == magic)
}

/// 读文件尾部采样（≤ 256B；文件过短则全文）。
pub fn read_tail(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).map_err(|e| format!("源读取失败: {e}"))?;
    let len = f
        .metadata()
        .map_err(|e| format!("源元数据读取失败: {e}"))?
        .len();
    let start = len.saturating_sub(256);
    f.seek(SeekFrom::Start(start))
        .map_err(|e| format!("源定位失败: {e}"))?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    f.read_to_end(&mut buf)
        .map_err(|e| format!("尾部采样失败: {e}"))?;
    Ok(buf)
}

// ---------------------------------------------------------------- 迁移分派 --

/// `format.migrate` 能力方法分派（其余方法显式拒绝）。
///
/// X42 双层错误模型：业务错误码以 `CODE: message` 前缀透传
/// （Host 侧提取 source_code 展示原码与引导）。
pub fn handler(method: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
    match method {
        super::fmt_methods::FORMAT_MIGRATE => {
            let p = crate::MigrateParams::from_value(params)
                .map_err(|e| format!("MF-PLUGIN-MANIFEST-INVALID: {e}"))?;
            let work = std::path::PathBuf::from(&p.work_dir);
            let source = crate::guard_path(&work, Path::new(&p.input_path))?;
            if !source.is_file() {
                return Err(format!("源不是文件: {}", source.display()));
            }
            let tail = read_tail(&source)?;
            match classify(
                source
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default(),
                &tail,
            ) {
                QmcVariant::StaticMap { .. } => crate::run_migrate(&p, &|raw, _p| {
                    // ekey 对静态表变体无意义：显式忽略（不静默当密钥用）
                    qmc_map_transform(raw)
                }),
                v @ (QmcVariant::StagTail | QmcVariant::QtagTail) => Err(format!(
                    "QMC-VARIANT-STAG-UNSUPPORTED: {} 变体为逐曲 ekey（账号绑定 DRM），\
                     按 RFC-0002 §2.3 仅识别报告、不迁移；\
                     如你有合法持有的解密授权，请在 issue 中说明场景",
                    if matches!(v, QmcVariant::StagTail) {
                        "STag(mflac)"
                    } else {
                        "QTag(mgg)"
                    }
                )),
                QmcVariant::Unknown => {
                    // 非本插件形态：恒等变换 → 产物双验失败 → 隔离区
                    // （失败显式可见，绝不静默删除）
                    crate::run_migrate(&p, &|raw, _p| raw.to_vec())
                }
            }
        }
        other => Err(format!(
            "MF-PLUGIN-METHOD-UNKNOWN: 本插件不服务该方法: {other}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_key_matches_c_reference() {
        // C 参考：i ≤ 0x7FFF → map[i & 0x7F]；i > 0x7FFF → map[(i % 0x7FFF) & 0x7F]
        assert_eq!(encode_key(0), 0xc3);
        assert_eq!(encode_key(1), 0x4a);
        assert_eq!(encode_key(0x7F), 0x4a); // 0x7F & 0x7F → 表[0x7F] = 0x4a
        assert_eq!(encode_key(0x80), 0xc3); // 0x80 & 0x7F = 0 → 表[0]
        assert_eq!(encode_key(0x7FFF), 0x4a);
        assert_eq!(encode_key(0x8000), 0x4a); // 0x8000 % 0x7FFF = 1 → 表[1]
        assert_eq!(encode_key(0xFFFF), 0x4a); // 0xFFFF = 2×0x7FFF + 1 → 余 1 → 表[1]
        assert_eq!(encode_key(0x8001), 0xd6); // 0x8001 % 0x7FFF = 2 → 表[2] = 0xd6
                                              // XOR 自逆：加密 == 解密（fixture 构造端 = 解密端同表镜像）
        let data = b"hello qmc";
        assert_eq!(qmc_map_transform(&qmc_map_transform(data)), data.to_vec());
    }

    #[test]
    fn classify_prefers_tail_magic_over_extension() {
        // .qmcflac + STag 尾 → 尾标变体（字节事实优先）
        let mut tail = vec![0u8; 200];
        tail.extend_from_slice(b"\x00\x10STag");
        assert_eq!(classify("song.qmcflac", &tail), QmcVariant::StagTail);
        // 静态表扩展名
        assert_eq!(
            classify("song.qmc0", &[]),
            QmcVariant::StaticMap { out_ext: "mp3" }
        );
        assert_eq!(
            classify("song.qmcflac", &[]),
            QmcVariant::StaticMap { out_ext: "flac" }
        );
        assert_eq!(
            classify("song.qmcogg", &[0u8; 32]),
            QmcVariant::StaticMap { out_ext: "ogg" }
        );
        // 尾标系扩展名（无尾标实测）→ 保守按尾标家族申报
        assert_eq!(classify("song.mflac0", &[]), QmcVariant::StagTail);
        assert_eq!(classify("song.mgg1", &[0u8; 32]), QmcVariant::StagTail);
        // mflac/mgg 无数字形态 = 静态表（附录 D），但带尾标则尾探测优先
        assert_eq!(
            classify("song.mflac", &[]),
            QmcVariant::StaticMap { out_ext: "flac" }
        );
        assert_eq!(
            classify("song.mgg", &[0u8; 32]),
            QmcVariant::StaticMap { out_ext: "ogg" }
        );
        // QTag
        let mut qt = vec![0u8; 200];
        qt.extend_from_slice(b"QTag\x01\x02");
        assert_eq!(classify("song.mgg", &qt), QmcVariant::QtagTail);
        // 未知扩展名
        assert_eq!(classify("song.mp3", &[]), QmcVariant::Unknown);
        // magic 驻留尾部窗口（最后 64B）内 → 命中
        let mut tail_in = vec![0u8; 60];
        tail_in.extend_from_slice(b"STag"); // 距尾 0
        assert_eq!(classify("song.qmcflac", &tail_in), QmcVariant::StagTail);
        // magic 距尾 >64B（采样中段偶然序列）→ 不命中，回退扩展名
        let mut mid = vec![0u8; 64];
        mid.extend_from_slice(b"STag");
        mid.extend_from_slice(&[0u8; 200]); // magic 距尾 204B
        assert_eq!(
            classify("song.qmcflac", &mid),
            QmcVariant::StaticMap { out_ext: "flac" }
        );
    }
}
