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

fn migrate_params(root: &Path, source: &Path, out_dir: &Path) -> MigrateParams {
    MigrateParams {
        work_root: root.display().to_string(),
        source_path: source.display().to_string(),
        output_dir: out_dir.display().to_string(),
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
    std::fs::write(lib.join("song.kwm"), musicforge_format_plugins::kwm::kwm_wrap(&plain))
        .unwrap();

    let out_dir = root.join("out");
    let r = run_migrate(
        &migrate_params(&root, &lib.join("song.kwm"), &out_dir),
        &musicforge_format_plugins::kwm::kwm_transform,
    )
    .unwrap();
    let target = out_dir.join("song.wav");
    assert_eq!(r["output_path"], target.display().to_string());
    assert_eq!(r["verification"]["magic"], "RIFF/WAVE");
    assert_eq!(r["verification"]["sample_rate"], 44100);
    assert_eq!(r["verification"]["channels"], 1);
    assert!(r["audit"]["source_sha256"].as_str().unwrap().len() == 64);
    assert_eq!(r["audit"]["quarantined"], false);
    assert!(target.exists(), "产物必须落盘");
    assert!(!root.join("out").join("song.migrating.tmp").exists(), "临时文件必须已改名");

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
    std::fs::write(lib.join("song.kwm"), musicforge_format_plugins::kwm::kwm_wrap(&plain))
        .unwrap();
    std::fs::create_dir_all(root.join("out")).unwrap();
    std::fs::write(root.join("out").join("song.wav"), b"PRE-EXISTING").unwrap();

    let err = run_migrate(
        &migrate_params(&root, &lib.join("song.kwm"), &root.join("out")),
        &musicforge_format_plugins::kwm::kwm_transform,
    )
    .unwrap_err();
    assert!(err.contains("MF-OUTPUT-EXISTS"), "覆盖企图必须显式拒绝: {err}");
    assert_eq!(
        std::fs::read(root.join("out").join("song.wav")).unwrap(),
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

    let err = run_migrate(
        &migrate_params(&root, &lib.join("junk.kwm"), &root.join("out")),
        &|raw| raw.to_vec(),
    )
    .unwrap_err();
    assert!(err.contains("magic") || err.contains("隔离"), "{err}");
    // 隔离区落位：.musicforge/quarantine/<task>/ 下必有产物残留（不静默删除）
    let qdir = root.join(".musicforge").join("quarantine");
    let entries: Vec<_> = std::fs::read_dir(&qdir)
        .unwrap()
        .filter_map(|e| e.ok())
        .flat_map(|e| std::fs::read_dir(e.path()).unwrap().filter_map(|x| x.ok()).collect::<Vec<_>>())
        .collect();
    assert!(!entries.is_empty(), "隔离区必须保留失败产物: {err}");
    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------- 协议分派 --

#[test]
fn kwm_handler_rejects_unknown_method_loudly() {
    let err = musicforge_format_plugins::kwm::handler(
        "ai.identify_track",
        &serde_json::json!({}),
    )
    .unwrap_err();
    assert!(err.contains("MF-PLUGIN-METHOD-UNKNOWN"), "{err}");
    assert!(!err.contains("format.migrate"));
}

#[test]
fn migrate_params_rejects_missing_fields() {
    let err = MigrateParams::from_value(&serde_json::json!({"work_root": "x"})).unwrap_err();
    assert!(err.contains("source_path"), "缺字段显式报错: {err}");
    assert_eq!(fmt_methods::FORMAT_MIGRATE, "format.migrate");
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
    let out_dir = root.join("out");
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::create_dir_all(&out_dir).unwrap();
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
    let req1 = serde_json::json!({"id":"r1","method":"plugin.manifest","params":{}});
    let req2 = serde_json::json!({"id":"r2","method":"format.migrate","params":{
        "work_root": root.display().to_string(),
        "source_path": lib.join("song.kwm").display().to_string(),
        "output_dir": out_dir.display().to_string(),
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
    assert_eq!(m["result"]["kind"], "format-adapter", "L3 类别声明: {m}");
    assert_eq!(m["result"]["network"], false, "格式插件强制离线");
    let r2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(r2["result"]["verification"]["magic"], "RIFF/WAVE");
    assert_eq!(r2["result"]["verification"]["sample_rate"], 44100);
    assert!(out_dir.join("song.wav").exists(), "迁移产物必须落盘");

    let status = child.wait().unwrap();
    assert!(status.success());
    std::fs::remove_dir_all(&root).ok();
}
