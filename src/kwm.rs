//! `kwm-migration`（Kuwo .kwm，B 级申报）：本地格式迁移参考实现。
//!
//! 算法（公开文档化形态）：文件头 16 字节 = AES-128-ECB（固定密钥
//! `ylzsxkwm`）加密的音频密钥；其余字节 = 音频与该密钥逐字节循环 XOR。
//!
//! **兼容性申报**（PLUGIN_POLICY §4）：自洽 roundtrip + 产物 magic/属性双验
//! 已测试钉死；与真实持有样本的互操作验证 pending——未经样本验证前按
//! 「实验」状态申报。仅处理用户合法持有的本地文件；永不联网、永不改源。

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

const KWM_KEY: &[u8; 8] = b"ylzsxkwm";
/// AES-128 密钥 = 8 字节种子右填充零（公开文档化形态：固定 16 字节 `ylzsxkwm\0\0…`）。
const KWM_KEY16: [u8; 16] = [
    b'y', b'l', b'z', b's', b'x', b'k', b'w', b'm', 0, 0, 0, 0, 0, 0, 0, 0,
];

/// 解出内嵌 16 字节音频密钥（文件头 16 字节，AES-128-ECB）。
pub fn extract_audio_key(raw: &[u8]) -> Result<[u8; 16], String> {
    if raw.len() < 16 {
        return Err("文件过短：不足 16 字节头部".to_string());
    }
    let cipher = Aes128::new(GenericArray::from_slice(&KWM_KEY16));
    let mut block = GenericArray::clone_from_slice(&raw[..16]);
    cipher.decrypt_block(&mut block);
    // 旧实现以 8 字节种子的前缀语义校验：解出的密钥前 8 字节应回显种子
    if &block[..8] != KWM_KEY {
        return Err("头部密钥解出失败：不是 .kwm 形态（前 8 字节不回显种子）".to_string());
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&block);
    Ok(key)
}

/// `.kwm` → 音频明文字节（主体与音频密钥循环 XOR）。
pub fn kwm_transform(raw: &[u8]) -> Vec<u8> {
    let key = match extract_audio_key(raw) {
        Ok(k) => k,
        Err(_) => return Vec::new(), // 变换失败 → 空产物 → 下游 magic 双验失败 → 隔离
    };
    raw[16..]
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % 16])
        .collect()
}

/// 逆变换（测试夹具：由明文构造 .kwm 形态字节）。
pub fn kwm_wrap(plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(&KWM_KEY16));
    let mut head = [0x11u8; 16]; // 任意 16 字节 → 加密后为头部
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut head));
    // 头部需满足「解出后前 8 字节 = 种子」：直接以种子 + 零作明文块加密
    let mut block = KWM_KEY16;
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
    head.copy_from_slice(&block);
    let key = KWM_KEY16;
    let mut out = head.to_vec();
    out.extend(plaintext.iter().enumerate().map(|(i, b)| b ^ key[i % 16]));
    out
}

/// `format.migrate` 能力方法分派（其余方法显式拒绝）。
pub fn handler(method: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
    match method {
        super::fmt_methods::FORMAT_MIGRATE => {
            let p = crate::MigrateParams::from_value(params)
                .map_err(|e| format!("MF-PLUGIN-MANIFEST-INVALID: {e}"))?;
            crate::run_migrate(&p, &|raw, _p| kwm_transform(raw))
        }
        other => Err(format!(
            "MF-PLUGIN-METHOD-UNKNOWN: 本插件不服务该方法: {other}"
        )),
    }
}
