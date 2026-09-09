//! QMCv2 流密码（X49：STag 尾标变体解密——用户自备 ekey，本地传递，零网络）。
//!
//! 出处：`qmc2-crypto`（bczhc/qmc-dec `third_party/qmc2-rust` 子模块，MIT+Apache-2.0
//! 双许可；其算法实现源自 Jixun 的 qmc2 系列）——README 审计表已登记。逐字移植，
//! 单测数值与参考源测试一一对应。
//!
//! **解密链**：`ekey(用户自备字符串)` → base64 →（EncV2 前缀则双阶段 TEA 剥壳）
//! → header(8B)+body → `derive_tea_key(header)` → TEA 解 body → **音频密钥**
//! → 按密钥长度分派（>300B → RC4 变体 / ≤300B → Map 变体）→ 逐字节流解密。
//!
//! **法务边界**（README 审计表 X49 裁决）：ekey 由用户从自己合法登录的客户端
//! 提取、经 `options.ekey` 本地传递；本模块**零网络、无 ekey 数据库**；
//! musicex 新版（需平台 API 凭据）不在此范围内。

use base64::Engine;

// ---------------------------------------------------------------- ekey 解析 --

/// EncV2 前缀（新版 ekey 双层封装标记）。
const QMC2_ENCV2_PREFIX: &[u8] = b"QQMusic EncV2,Key:";
/// EncV2 双阶段 TEA 常量（出处：qmc2-crypto key_dec.rs；MIT+Apache-2.0）。
const QMC2_ENCV2_STAGE1_KEY: &[u8] = b"386ZJY!@#*$%^&)(";
const QMC2_ENCV2_STAGE2_KEY: &[u8] = b"**#!(#$%&^a1cZ,T";

/// TEA 派生基础字节（seed=106）。
///
/// 参考源以 `simple_make_key(106, 8)` 浮点推导：
/// `b[i] = (100.0 * ((seed + i * 0.1_f32).tan().abs())) as u8`。
/// 此处直接以推导结果常量固化（跨平台 f32 tan 的 ULP 差异不影响本值，
/// 且与参考源单测期望逐字节一致），推导公式留档。
const SIMPLE_KEY_SEED106: [u8; 8] = [0x69, 0x56, 0x46, 0x38, 0x2b, 0x20, 0x15, 0x0b];

/// 由 ekey 头 8 字节派生 TEA 密钥（偶位取派生表、奇位取 ekey 头，交织填充）。
fn derive_tea_key(ekey_header: &[u8]) -> [u8; 16] {
    let mut tea_key = [0u8; 16];
    for i in (0..16).step_by(2) {
        tea_key[i] = SIMPLE_KEY_SEED106[i / 2];
        tea_key[i + 1] = ekey_header[i / 2];
    }
    tea_key
}

/// ekey 解析错误（X42：调用侧映射为 `QMC-EKEY-INVALID` 业务码）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EKeyParseError;

/// 解析用户自备 ekey → 音频密钥字节（header 8B + 解密 body）。
pub fn parse_ekey(ekey: &str) -> Result<Vec<u8>, EKeyParseError> {
    let ekey = ekey.trim_matches(char::from(0));
    let engine = base64::engine::general_purpose::STANDARD;
    let mut decoded = engine.decode(ekey).map_err(|_| EKeyParseError)?;

    if decoded.len() < 8 {
        return Err(EKeyParseError);
    }

    // EncV2 双层封装：双阶段 TEA 剥壳 → 内层 base64 → encv1 ekey
    if decoded.starts_with(QMC2_ENCV2_PREFIX) {
        let blob = &decoded[QMC2_ENCV2_PREFIX.len()..];
        let stage1 = tc_tea::decrypt(blob, QMC2_ENCV2_STAGE1_KEY).ok_or(EKeyParseError)?;
        let stage2 = tc_tea::decrypt(&stage1, QMC2_ENCV2_STAGE2_KEY).ok_or(EKeyParseError)?;
        let encv1 = engine.decode(&stage2).map_err(|_| EKeyParseError)?;
        decoded = encv1;
        if decoded.len() < 8 {
            return Err(EKeyParseError);
        }
    }

    let (header, body) = decoded.split_at(8);
    let tea_key = derive_tea_key(header);
    let body = tc_tea::decrypt(body, tea_key).ok_or(EKeyParseError)?;
    let mut key = Vec::with_capacity(8 + body.len());
    key.extend_from_slice(header);
    key.extend_from_slice(&body);
    Ok(key)
}

// ---------------------------------------------------------------- Map 变体 --

/// QMCv2 Map 变体（密钥映射流密码；≤300B 密钥）。
pub struct Qmc2MapCipher {
    key: Vec<u8>,
}

impl Qmc2MapCipher {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// 密钥字节按索引移位混合（u8 环绕移位，与参考源逐字一致）。
    fn scramble_by_index(value: u8, index: usize) -> u8 {
        let rotation = (index as u32).wrapping_add(4) & 0b111;
        let left = value.wrapping_shl(rotation);
        let right = value.wrapping_shr(rotation);
        left | right
    }

    /// 偏移 → 密钥流字节（0x7FFF 周期回绕 + 平方索引 + 混淆）。
    fn map_l(&self, offset: usize) -> u8 {
        let mut offset_local = offset;
        if offset_local > 0x7FFF {
            offset_local %= 0x7FFF;
        }
        let index = (offset_local * offset_local + 71214) % self.key.len();
        Self::scramble_by_index(self.key[index], index)
    }

    pub fn decrypt(&self, offset: usize, buf: &mut [u8]) {
        buf.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte ^= self.map_l(offset + i);
        });
    }
}

// ---------------------------------------------------------------- RC4 变体 --

/// 首段尺寸（首 0x80 字节用独立算法）。
const FIRST_SEGMENT_SIZE: usize = 0x80;
/// 其余段尺寸（0x1400 = 5120B；段内 RC4 流按段密钥重置）。
const OTHER_SEGMENT_SIZE: usize = 0x1400;

/// QMCv2 RC4 变体（>300B 密钥；mflac0/mflac1 主流形态）。
pub struct Qmc2Rc4Cipher {
    /// RC4 种子盒（KSA 后）
    s: Vec<u8>,
    /// 哈希基数（段密钥计算用）
    hash: u32,
    /// RC4 密钥
    rc4_key: Vec<u8>,
}

impl Qmc2Rc4Cipher {
    pub fn new(rc4_key: &[u8]) -> Self {
        let n = rc4_key.len();
        let mut s: Vec<u8> = (0..n).map(|i| i as u8).collect();
        let mut j = 0usize;
        for (i, &key) in rc4_key.iter().enumerate() {
            j = j.wrapping_add(s[i] as usize).wrapping_add(key as usize) % n;
            s.swap(i, j);
        }
        Self {
            s,
            hash: Self::calc_hash_base(rc4_key),
            rc4_key: rc4_key.to_vec(),
        }
    }

    /// 哈希基数（跳零 + 环绕乘上溢即止——与参考源逐字一致）。
    fn calc_hash_base(data: &[u8]) -> u32 {
        let mut hash: u32 = 1;
        for &value in data.iter() {
            let value = u32::from(value);
            if value == 0 {
                continue;
            }
            let next_hash = hash.wrapping_mul(value);
            if next_hash == 0 || next_hash <= hash {
                break;
            }
            hash = next_hash;
        }
        hash
    }

    /// 段密钥（hash / (id+1)*seed * 100 截断）。
    fn calc_segment_key(&self, id: usize, seed: u8) -> usize {
        let dividend = f64::from(self.hash);
        let divisor = ((id + 1) * usize::from(seed)) as f64;
        let key = dividend / divisor * 100.0;
        key as u64 as usize
    }

    /// RC4 下一个异或字节（PRGA 单步）。
    fn rc4_derive(n: usize, s: &mut [u8], j: &mut usize, k: &mut usize) -> u8 {
        *j = (*j + 1) % n;
        *k = (usize::from(s[*j]) + *k) % n;
        s.swap(*j, *k);
        let index = usize::from(s[*j]) + usize::from(s[*k]);
        s[index % n]
    }

    fn encode_first_segment(&self, offset: usize, buf: &mut [u8]) {
        let n = self.rc4_key.len();
        for (offset, b) in (offset..).zip(buf.iter_mut()) {
            let key1 = self.rc4_key[offset % n];
            let key2 = self.calc_segment_key(offset, key1);
            *b ^= self.rc4_key[key2 % n];
        }
    }

    fn encode_other_segment(&self, offset: usize, buf: &mut [u8]) {
        let seg_id = offset / OTHER_SEGMENT_SIZE;
        let seg_id_small = seg_id & 0x1FF;
        let mut discard_count = self.calc_segment_key(seg_id, self.rc4_key[seg_id_small]) & 0x1FF;
        discard_count += offset % OTHER_SEGMENT_SIZE;

        let n = self.rc4_key.len();
        let mut s = self.s.clone();
        let mut j = 0usize;
        let mut k = 0usize;
        for _ in 0..discard_count {
            Self::rc4_derive(n, &mut s, &mut j, &mut k);
        }
        for b in buf.iter_mut() {
            *b ^= Self::rc4_derive(n, &mut s, &mut j, &mut k);
        }
    }

    pub fn decrypt(&self, offset: usize, buf: &mut [u8]) {
        let mut offset = offset;
        let mut len = buf.len();
        let mut i = 0usize;

        // 首段独立算法
        if offset < FIRST_SEGMENT_SIZE {
            let len_processed = std::cmp::min(len, FIRST_SEGMENT_SIZE - offset);
            self.encode_first_segment(offset, &mut buf[i..i + len_processed]);
            i += len_processed;
            len -= len_processed;
            offset += len_processed;
        }
        // 对齐到段边界
        let to_align = offset % OTHER_SEGMENT_SIZE;
        if to_align != 0 {
            let len_processed = std::cmp::min(len, OTHER_SEGMENT_SIZE - to_align);
            self.encode_other_segment(offset, &mut buf[i..i + len_processed]);
            i += len_processed;
            len -= len_processed;
            offset += len_processed;
        }
        // 整段
        while len > OTHER_SEGMENT_SIZE {
            self.encode_other_segment(offset, &mut buf[i..i + OTHER_SEGMENT_SIZE]);
            i += OTHER_SEGMENT_SIZE;
            len -= OTHER_SEGMENT_SIZE;
            offset += OTHER_SEGMENT_SIZE;
        }
        // 剩余
        if len > 0 {
            self.encode_other_segment(offset, &mut buf[i..i + len]);
        }
    }
}

// ---------------------------------------------------------------- 工厂分派 --

/// QMCv2 密码器（ekey → 按密钥长度自动分派 Map/RC4）。
pub enum Qmc2Cipher {
    Map(Qmc2MapCipher),
    Rc4(Qmc2Rc4Cipher),
}

impl Qmc2Cipher {
    /// 解析 ekey 并构造密码器（key.len() > 300 → RC4，否则 Map——参考源分派阈值）。
    pub fn from_ekey(ekey: &str) -> Result<Self, EKeyParseError> {
        let key = parse_ekey(ekey)?;
        Ok(if key.len() > 300 {
            Self::Rc4(Qmc2Rc4Cipher::new(&key))
        } else {
            Self::Map(Qmc2MapCipher::new(&key))
        })
    }

    /// 全流解密（从偏移 0 起；XOR 自逆——加密端 fixture 复用同函数）。
    pub fn decrypt(&self, raw: &[u8]) -> Vec<u8> {
        let mut out = raw.to_vec();
        match self {
            Self::Map(c) => c.decrypt(0, &mut out),
            Self::Rc4(c) => c.decrypt(0, &mut out),
        }
        out
    }
}

// ---------------------------------------------------------------- 单测 --

#[cfg(test)]
mod tests {
    use super::*;

    /// 参考源 key_dec.rs 测试钉死值：derive_tea_key 交织形态。
    #[test]
    fn derive_tea_key_interleaves() {
        let ekey_header = [0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8];
        let expected = [
            0x69, 0xf1, 0x56, 0xf2, 0x46, 0xf3, 0x38, 0xf4, 0x2b, 0xf5, 0x20, 0xf6, 0x15, 0xf7,
            0x0b, 0xf8,
        ];
        assert_eq!(derive_tea_key(&ekey_header), expected);
    }

    /// 参考源 key_dec.rs 真实 fixture：ekey 字符串 → 明文 key。
    #[test]
    fn parse_ekey_reference_fixture() {
        let expected_key = "This is a test key for test purpose :D";
        let ekey = "VGhpcyBpcyBHFWEh4cjZ1Vi7rJ56XeoPlqGM1sxBGPg7mt89umKclFBr9iqfmFdS";
        let key = parse_ekey(ekey).unwrap();
        assert_eq!(std::str::from_utf8(&key).unwrap(), expected_key);
    }

    #[test]
    fn parse_ekey_rejects_garbage() {
        assert_eq!(parse_ekey("!!!not-base64!!!"), Err(EKeyParseError));
        assert_eq!(parse_ekey(&base64_short()), Err(EKeyParseError));
    }

    fn base64_short() -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(b"ab")
    }

    /// 参考源 qmc2_map.rs 测试钉死值：16B key "A".."P" 在 offset 0 的解密输出。
    #[test]
    fn map_cipher_reference_values() {
        let key: [u8; 16] = [
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
            0x4F, 0x50,
        ];
        let expected1 = [
            0x3F, 0x8A, 0xC1, 0x49, 0x3F, 0x49, 0xC1, 0x8A, 0x3F, 0x8A, 0xC1, 0x49, 0x3F, 0x49,
            0xC1, 0x8A,
        ];
        let expected2 = [
            0x8A, 0x3F, 0x8A, 0xC1, 0x49, 0x3F, 0x49, 0xC1, 0x8A, 0x8A, 0xC1, 0x49, 0x3F, 0x49,
            0xC1, 0x8A,
        ];
        let c = Qmc2MapCipher::new(&key);
        let mut data = [0u8; 16];
        c.decrypt(0, &mut data);
        assert_eq!(data, expected1);
        let mut data = [0u8; 16];
        c.decrypt(0x7FFF - 8, &mut data);
        assert_eq!(data, expected2);
    }

    /// 参考源 qmc2_rc4.rs 测试钉死值：255B 顺序 key 的各段解密输出。
    #[test]
    fn rc4_cipher_reference_values() {
        let rc4_key: Vec<u8> = (0..255).map(|i| i as u8).collect();
        let c = Qmc2Rc4Cipher::new(&rc4_key);

        let mut data = [0u8; 16];
        c.decrypt(0, &mut data);
        assert_eq!(
            data,
            [0, 50, 16, 8, 5, 3, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0],
            "首段"
        );

        let mut data = [0u8; 16];
        c.decrypt(FIRST_SEGMENT_SIZE - 8, &mut data);
        assert_eq!(
            data,
            [0, 0, 0, 0, 0, 0, 0, 0, 141, 97, 122, 193, 166, 101, 233, 214],
            "首段/次段边界"
        );

        let mut data = [0u8; 16];
        c.decrypt(OTHER_SEGMENT_SIZE - 8, &mut data);
        assert_eq!(
            data,
            [118, 193, 176, 83, 10, 98, 105, 234, 151, 56, 198, 1, 226, 173, 127, 4],
            "两段边界"
        );

        let mut data = [0u8; 16];
        c.decrypt(OTHER_SEGMENT_SIZE, &mut data);
        assert_eq!(
            data,
            [151, 56, 198, 1, 226, 173, 127, 4, 181, 165, 171, 21, 82, 152, 195, 210],
            "第二段起始"
        );
    }

    /// 参考源 qmc2_rc4.rs：hash_base 跳零 + 上溢即止。
    #[test]
    fn hash_base_reference_values() {
        assert_eq!(Qmc2Rc4Cipher::calc_hash_base(&[1u8, 99]), 1);
        let ff = [0xffu8; 16];
        assert_eq!(Qmc2Rc4Cipher::calc_hash_base(&ff), 0xfc05fc01);
        let mut with_zeros = vec![0u8];
        with_zeros.extend_from_slice(&[0xffu8; 8]);
        with_zeros.push(0);
        with_zeros.extend_from_slice(&[0xffu8; 8]);
        assert_eq!(Qmc2Rc4Cipher::calc_hash_base(&with_zeros), 0xfc05fc01);
    }

    /// XOR 自逆：Map/RC4 解密 == 加密（fixture 构造端镜像）。
    #[test]
    fn ciphers_are_xor_self_inverse() {
        let key = vec![0x41u8; 16];
        let data = b"self inverse check";
        let c = Qmc2MapCipher::new(&key);
        let mut enc = data.to_vec();
        c.decrypt(0, &mut enc);
        c.decrypt(0, &mut enc);
        assert_eq!(enc, data.to_vec());

        let rkey: Vec<u8> = (0..255).map(|i| (i * 7) as u8).collect();
        let rc = Qmc2Rc4Cipher::new(&rkey);
        let mut enc = data.to_vec();
        rc.decrypt(0, &mut enc);
        rc.decrypt(0, &mut enc);
        assert_eq!(enc, data.to_vec());
    }

    /// 工厂分派：key ≤300 → Map；>300 → RC4。
    #[test]
    fn factory_dispatches_by_key_length() {
        // ekey fixture 解出 key = "This is a test key for test purpose :D"（38B → Map）
        let ekey = "VGhpcyBpcyBHFWEh4cjZ1Vi7rJ56XeoPlqGM1sxBGPg7mt89umKclFBr9iqfmFdS";
        assert!(matches!(
            Qmc2Cipher::from_ekey(ekey).unwrap(),
            Qmc2Cipher::Map(_)
        ));
        assert!(parse_ekey("zzz").is_err());
    }
}
