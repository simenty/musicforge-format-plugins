//! 离线契约测试：路径守卫 / 迁移全流程 / 覆盖拒绝 / 隔离区 / 协议分派。
//! 全部不联网；fixture 自构造（合法最小 WAV，lofty 可解析）。

use std::path::Path;

use musicforge_format_plugins::{fmt_methods, guard_path, run_migrate, MigrateParams};

/// 合法最小 WAV（RIFF/PCM，lofty 可解析）。
fn wav_bytes(sample_rate: u32, bits: u16) -> Vec<u8> {
    let data = vec![0u8; 512];
    let byte_rate = sample_rate * bits as u32 / 8;
    let block_align = bits / 8;
    let mut v = Vec::new();
    v.extend_from_slice(b"RIFF");
    v.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
    v.extend_from_slice(b"WAVE");
    v.extend_from_slice(b"fmt ");
    v.extend_from_slice(&16u32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&sample_rate.to_le_bytes());
    v.extend_from_slice(&byte_rate.to_le_bytes());
    v.extend_from_slice(&block_align.to_le_bytes());
    v.extend_from_slice(&bits.to_le_bytes());
    v.extend_from_slice(b"data");
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v.extend_from_slice(&data);
    v
}

fn uniq_root(tag: &str) -> std::path::PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("mf-fmt-{tag}-{n}-{}", std::process::id()))
}

fn migrate_params(source: &Path, work_dir: &Path) -> MigrateParams {
    MigrateParams {
        job_id: format!("job-{}", std::process::id()),
        input_path: source.display().to_string(),
        output_path: work_dir.join("output").display().to_string(),
        work_dir: work_dir.display().to_string(),
        ekey: None,
    }
}

// ---------------------------------------------------------------- 路径守卫 --

#[test]
fn guard_rejects_escape_and_outside_root() {
    let root = uniq_root("guard");
    std::fs::create_dir_all(root.join("lib")).unwrap();
    let inside = root.join("lib").join("a.wav");
    std::fs::write(&inside, b"x").unwrap();

    // 边界内：canonical 化通过
    assert!(guard_path(&root, &inside).is_ok());

    // `..` 组件：显式拒绝
    let escape = root.join("lib").join("..").join("evil.wav");
    let err = guard_path(&root, &escape).unwrap_err();
    assert!(err.contains("MF-DIR-NOT-AUTHORIZED"), "{err}");

    // 边界外绝对路径：拒绝
    let outside = std::env::temp_dir().join(format!("mf-outside-{}.txt", std::process::id()));
    std::fs::write(&outside, b"x").unwrap();
    let err = guard_path(&root, &outside).unwrap_err();
    assert!(err.contains("MF-DIR-NOT-AUTHORIZED"), "{err}");
    std::fs::remove_file(&outside).ok();

    // 边界内不存在的新目标（output_dir 语义）：允许（对存在前缀 canonical 化）
    let new_dir = root.join("out");
    assert!(guard_path(&root, &new_dir).is_ok());

    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------- 迁移流程 --

#[test]
fn migrate_happy_path_verifies_and_audits() {
    let root = uniq_root("happy");
    let lib = root.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    // 明文 = 合法 WAV；夹具逆变换构造 .kwm 形态字节
    let plain = wav_bytes(44100, 16);
    std::fs::write(
        lib.join("song.kwm"),
        musicforge_format_plugins::kwm::kwm_wrap(&plain),
    )
    .unwrap();

    // v0.1（X41）：源与产物都在 work_dir 内；artifacts 相对路径出站
    let r = run_migrate(&migrate_params(&lib.join("song.kwm"), &root), &|raw, _p| {
        musicforge_format_plugins::kwm::kwm_transform(raw)
    })
    .unwrap();
    let target = root.join("song.wav");
    assert_eq!(r["status"], "success");
    assert_eq!(r["output_format"], "wav");
    assert_eq!(
        r["artifacts"],
        serde_json::json!(["song.wav"]),
        "artifacts 相对 work_dir"
    );
    assert_eq!(r["output_path"], target.display().to_string());
    assert_eq!(r["verification"]["magic"], "RIFF/WAVE");
    assert_eq!(r["verification"]["sample_rate"], 44100);
    assert_eq!(r["verification"]["channels"], 1);
    assert!(r["audit"]["source_sha256"].as_str().unwrap().len() == 64);
    assert_eq!(r["audit"]["quarantined"], false);
    assert!(target.exists(), "产物必须落盘");

    // 原源文件原位未动（绝不改源）
    assert!(lib.join("song.kwm").exists());

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn migrate_refuses_to_overwrite_existing_target() {
    let root = uniq_root("overwrite");
    let lib = root.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    let plain = wav_bytes(44100, 16);
    std::fs::write(
        lib.join("song.kwm"),
        musicforge_format_plugins::kwm::kwm_wrap(&plain),
    )
    .unwrap();
    // v0.1：产物在 work_dir 根——预置同位冲突目标
    std::fs::write(root.join("song.wav"), b"PRE-EXISTING").unwrap();

    let err = run_migrate(&migrate_params(&lib.join("song.kwm"), &root), &|raw, _p| {
        musicforge_format_plugins::kwm::kwm_transform(raw)
    })
    .unwrap_err();
    assert!(
        err.contains("MF-OUTPUT-EXISTS"),
        "覆盖企图必须显式拒绝: {err}"
    );
    assert_eq!(
        std::fs::read(root.join("song.wav")).unwrap(),
        b"PRE-EXISTING",
        "既有目标内容不变"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn migrate_quarantines_garbage_output_and_fails_loudly() {
    let root = uniq_root("quarantine");
    let lib = root.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    // 恒等变换（不解密）→ 产物不是可识别音频 → 双验失败 → 隔离
    std::fs::write(lib.join("junk.kwm"), b"not-a-kwm-file-at-all........").unwrap();

    let err = run_migrate(&migrate_params(&lib.join("junk.kwm"), &root), &|raw, _p| {
        raw.to_vec()
    })
    .unwrap_err();
    assert!(err.contains("magic") || err.contains("隔离"), "{err}");
    // 隔离区落位：.musicforge/quarantine/<task>/ 下必有产物残留（不静默删除）
    let qdir = root.join(".musicforge").join("quarantine");
    let entries: Vec<_> = std::fs::read_dir(&qdir)
        .unwrap()
        .filter_map(|e| e.ok())
        .flat_map(|e| {
            std::fs::read_dir(e.path())
                .unwrap()
                .filter_map(|x| x.ok())
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(!entries.is_empty(), "隔离区必须保留失败产物: {err}");
    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------- 协议分派 --

#[test]
fn kwm_handler_rejects_unknown_method_loudly() {
    let err = musicforge_format_plugins::kwm::handler("ai.identify_track", &serde_json::json!({}))
        .unwrap_err();
    assert!(err.contains("MF-PLUGIN-METHOD-UNKNOWN"), "{err}");
    assert!(!err.contains("format.migrate"));
}

#[test]
fn migrate_params_rejects_missing_fields() {
    let err = MigrateParams::from_value(&serde_json::json!({"job_id": "j"})).unwrap_err();
    assert!(err.contains("input_path"), "缺字段显式报错: {err}");
    // v0.1：ekey 走 options 包裹（RFC-0002/X38）
    let p = MigrateParams::from_value(&serde_json::json!({
        "job_id": "j", "input_path": "a", "output_path": "b", "work_dir": "w",
        "options": {"ekey": "k"}
    }))
    .unwrap();
    assert_eq!(p.ekey.as_deref(), Some("k"));
    assert_eq!(fmt_methods::FORMAT_MIGRATE, "format.migrate");
}

// ---------------------------------------------------------------- QMC（RFC-0002）--

/// 合法最小 FLAC（fLaC + STREAMINFO，lofty 可读出 44100Hz/1ch/16bit）。
fn flac_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"fLaC");
    v.push(0x80); // last-metadata-block=1，type=0（STREAMINFO）
    v.extend_from_slice(&34u32.to_be_bytes()[1..]); // 24bit 块长
    v.extend_from_slice(&4096u16.to_be_bytes()); // min block size
    v.extend_from_slice(&4096u16.to_be_bytes()); // max block size
    v.extend_from_slice(&[0, 0, 0]); // min frame size（u24）
    v.extend_from_slice(&[0, 0, 0]); // max frame size（u24）
                                     // 20bit sample_rate(44100) | 3bit channels-1(=0，零项省略) | 5bit bps-1(15→16bit) | 36bit total(128)
    let packed: u64 = (44100u64 << 44) | (15u64 << 36) | 128u64;
    v.extend_from_slice(&packed.to_be_bytes());
    v.extend_from_slice(&[0u8; 16]); // md5
    v
}

#[test]
fn qmc_static_roundtrip_flac_migrates_and_verifies() {
    let root = uniq_root("qmc-flac");
    let lib = root.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    // 明文 = 合法 FLAC；XOR 自逆：同一变换即加密端（合成 fixture 镜像）
    let plain = flac_bytes();
    std::fs::write(
        lib.join("song.qmcflac"),
        musicforge_format_plugins::qmc::qmc_map_transform(&plain),
    )
    .unwrap();

    let p = migrate_params(&lib.join("song.qmcflac"), &root);
    // ekey 对静态表变体无意义：即便误传入也必须被忽略（不静默当密钥用）
    let mut p = p;
    p.ekey = Some("DEADBEEF".to_string());
    let r = run_migrate(&p, &|raw, _p| {
        musicforge_format_plugins::qmc::qmc_map_transform(raw)
    })
    .unwrap();

    let target = root.join("song.flac");
    assert_eq!(r["status"], "success");
    assert_eq!(
        r["output_format"], "flac",
        "静态表 qmcflac → flac（附录 D）"
    );
    assert_eq!(r["artifacts"], serde_json::json!(["song.flac"]));
    assert_eq!(r["verification"]["magic"], "fLaC");
    assert_eq!(r["verification"]["sample_rate"], 44100);
    assert_eq!(r["verification"]["channels"], 1);
    assert!(target.exists());
    assert!(lib.join("song.qmcflac").exists(), "源原样（绝不改源）");
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn qmc_stag_tail_explicit_refusal() {
    let root = uniq_root("qmc-stag");
    let lib = root.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    // 合成 STag 尾标形态：载荷 + STag magic（RFC §5：尾探测优先于扩展名）
    let mut raw = flac_bytes(); // 载荷形似 flac（仅 fixture 语义）
    raw.extend_from_slice(&[0u8; 128]);
    raw.extend_from_slice(b"STag\x10\x00\x00\x00");
    std::fs::write(lib.join("song.mflac"), &raw).unwrap();
    let before = std::fs::read(lib.join("song.mflac")).unwrap();

    let err = musicforge_format_plugins::qmc::handler(
        "format.migrate",
        &serde_json::json!({
            "job_id": "j",
            "input_path": lib.join("song.mflac").display().to_string(),
            "output_path": root.join("output").display().to_string(),
            "work_dir": root.display().to_string(),
            "options": {"ekey": "SOME-EKEY"}
        }),
    )
    .unwrap_err();
    // X42 双层模型：业务码前缀透传（host 提取 source_code）
    assert!(
        err.starts_with("QMC-VARIANT-STAG-UNSUPPORTED"),
        "STag = 账号绑定 DRM，显式拒绝: {err}"
    );
    // 源文件原样保留；无任何产物落盘
    assert_eq!(std::fs::read(lib.join("song.mflac")).unwrap(), before);
    assert!(!root.join("song.flac").exists());
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn qmc_stag_by_extension_without_tail_also_refused() {
    let root = uniq_root("qmc-mflac1");
    let lib = root.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    // .mflac1 无实测尾标：按附录 D 声明保守归尾标家族（requires_ekey 语义）
    std::fs::write(lib.join("song.mflac1"), b"payload-without-tag........").unwrap();

    let err = musicforge_format_plugins::qmc::handler(
        "format.migrate",
        &serde_json::json!({
            "job_id": "j",
            "input_path": lib.join("song.mflac1").display().to_string(),
            "output_path": root.join("output").display().to_string(),
            "work_dir": root.display().to_string(),
            "options": {}
        }),
    )
    .unwrap_err();
    assert!(err.starts_with("QMC-VARIANT-STAG-UNSUPPORTED"), "{err}");
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn qmc_unknown_payload_quarantines_not_silent() {
    let root = uniq_root("qmc-unknown");
    let lib = root.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    // .qmc3 声明扩展名但内容非 QMC 静态表形态 → 解出垃圾 → 双验失败 → 隔离
    std::fs::write(lib.join("junk.qmc3"), b"garbage-not-audio-...........").unwrap();

    let err = musicforge_format_plugins::qmc::handler(
        "format.migrate",
        &serde_json::json!({
            "job_id": "j",
            "input_path": lib.join("junk.qmc3").display().to_string(),
            "output_path": root.join("output").display().to_string(),
            "work_dir": root.display().to_string(),
            "options": {}
        }),
    )
    .unwrap_err();
    assert!(err.contains("隔离"), "失败显式可见（绝不静默删除）: {err}");
    let qdir = root.join(".musicforge").join("quarantine");
    let entries: Vec<_> = std::fs::read_dir(&qdir)
        .unwrap()
        .filter_map(|e| e.ok())
        .flat_map(|e| {
            std::fs::read_dir(e.path())
                .unwrap()
                .filter_map(|x| x.ok())
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(!entries.is_empty(), "隔离区必须保留失败产物");
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn qmc_handler_rejects_unknown_method_loudly() {
    let err = musicforge_format_plugins::qmc::handler("ai.identify_track", &serde_json::json!({}))
        .unwrap_err();
    assert!(err.contains("MF-PLUGIN-METHOD-UNKNOWN"), "{err}");
}

#[test]
fn qmc_sniff_magic_ogg_branch() {
    // T2 扩展：OggS 分支（qmcogg/qmc2 产物必需；无此分支会落 "bin"）
    assert_eq!(
        musicforge_format_plugins::sniff_magic(b"OggS\x00\x02"),
        Some("OggS")
    );
    assert_eq!(musicforge_format_plugins::sniff_magic(b"OggX"), None);
}

#[test]
fn qmc_binary_serves_init_and_migrate_over_stdio() {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let root = uniq_root("qmc-bin");
    let lib = root.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    let plain = flac_bytes();
    std::fs::write(
        lib.join("song.qmcflac"),
        musicforge_format_plugins::qmc::qmc_map_transform(&plain),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_qmc-migration"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let req1 = serde_json::json!({"id":"r1","method":"plugin.init","params":{
        "protocol_version": 1, "work_dir": root.display().to_string(),
        "locale": "zh-CN", "host_capabilities": {"batch": false, "events": false, "artifacts": true}
    }});
    let req2 = serde_json::json!({"id":"r2","method":"format.migrate","params":{
        "job_id": "job-qmc",
        "input_path": lib.join("song.qmcflac").display().to_string(),
        "output_path": root.join("output").display().to_string(),
        "work_dir": root.display().to_string(),
        "options": {}
    }});
    writeln!(stdin, "{}", req1).unwrap();
    writeln!(stdin, "{}", req2).unwrap();
    drop(stdin);

    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "恰两行响应: {out}");
    let m: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(
        m["result"]["manifest"]["name"], "qmc-migration",
        "B9: 清单名不漂移"
    );
    assert_eq!(m["result"]["manifest"]["kind"], "format-adapter");
    assert_eq!(m["result"]["manifest"]["network"], false);
    assert_eq!(m["result"]["manifest"]["ack_required"], true);
    let r2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(r2["result"]["status"], "success");
    assert_eq!(r2["result"]["artifacts"], serde_json::json!(["song.flac"]));
    assert_eq!(r2["result"]["verification"]["magic"], "fLaC");
    assert!(root.join("song.flac").exists());

    let status = child.wait().unwrap();
    assert!(status.success());
    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------- 进程级协议 --

/// 真实二进制全链路：spawn → manifest（kind=format-adapter/network=false）→
/// format.migrate（真解密+双验+落盘）→ EOF 退出。进程级等价于主仓 Host e2e。
#[test]
fn binary_serves_manifest_and_migrate_over_stdio() {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let root = uniq_root("bin");
    let lib = root.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    let plain = wav_bytes(44100, 16);
    std::fs::write(
        lib.join("song.kwm"),
        musicforge_format_plugins::kwm::kwm_wrap(&plain),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_kwm-migration"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // P6a-R：init 握手（v0.1）先行 + format.migrate（v0.1 形状，X41 出站）
    let req1 = serde_json::json!({"id":"r1","method":"plugin.init","params":{
        "protocol_version": 1, "work_dir": root.display().to_string(),
        "locale": "zh-CN", "host_capabilities": {"batch": false, "events": false, "artifacts": true}
    }});
    let req2 = serde_json::json!({"id":"r2","method":"format.migrate","params":{
        "job_id": "job-bin",
        "input_path": lib.join("song.kwm").display().to_string(),
        "output_path": root.join("output").display().to_string(),
        "work_dir": root.display().to_string(),
        "options": {}
    }});
    writeln!(stdin, "{}", req1).unwrap();
    writeln!(stdin, "{}", req2).unwrap();
    drop(stdin); // EOF → 服务环自然退出

    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "恰两行响应: {out}");
    let m: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(m["result"]["api_version"], "1.0.0", "init 返回协议版本");
    assert_eq!(
        m["result"]["manifest"]["kind"], "format-adapter",
        "L3 类别声明: {m}"
    );
    assert_eq!(
        m["result"]["manifest"]["network"], false,
        "格式插件强制离线"
    );
    // 稳定审计 B9 回归：清单名必须与 plugin.json/name 一致（此前环境变量缺省
    // 漂移为 "format-plugin" → ACK 闸永远失败）
    assert_eq!(
        m["result"]["manifest"]["name"], "kwm-migration",
        "B9: 清单名不得漂移"
    );
    let r2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(r2["result"]["status"], "success");
    assert_eq!(r2["result"]["artifacts"], serde_json::json!(["song.wav"]));
    assert_eq!(r2["result"]["verification"]["magic"], "RIFF/WAVE");
    assert_eq!(r2["result"]["verification"]["sample_rate"], 44100);
    assert!(
        root.join("song.wav").exists(),
        "迁移产物必须落盘（work_dir 内）"
    );

    let status = child.wait().unwrap();
    assert!(status.success());
    std::fs::remove_dir_all(&root).ok();
}
