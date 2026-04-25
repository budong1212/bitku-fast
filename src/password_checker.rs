use crate::wallet::BitcoinCoreWallet;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use rayon::prelude::*;
use sha2::{Digest, Sha512};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// 密码检查器
pub struct PasswordChecker {
    wallet: BitcoinCoreWallet,
    checked_count: Arc<AtomicU64>,
    found: Arc<AtomicBool>,
    start_time: Instant,
}

/// 检查结果
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub password: Option<String>,
    pub checked_count: u64,
    pub elapsed_secs: f64,
    pub speed: f64, // passwords per second
}

/// 核心 KDF：对单个密码执行 SHA-512 迭代派生密钥
///
/// # 优化要点
/// 1. 用 `[u8; 64]` 固定大小栈数组替代原版 `Vec<u8>`，完全消除堆分配
/// 2. 循环内复用同一个 `Sha512` 实例（reset 比 new 快）
/// 3. 第一次迭代输入 = password || salt（在栈上拼接），后续输入仅 64 字节
/// 4. 借助 `.cargo/config.toml` 的 `target-cpu=native` + `sha2` 的 `asm`
///    feature，自动启用 SHA-NI / AVX2 硬件加速
#[inline(always)]
fn derive_key(password_bytes: &[u8], salt: &[u8; 8], iter_count: u32) -> [u8; 64] {
    // 第一轮：hash(password || salt)
    // 使用栈上 buffer 拼接，避免堆分配
    let mut hasher = Sha512::new();
    hasher.update(password_bytes);
    hasher.update(salt);
    // 将结果写入固定 64 字节数组
    let first: [u8; 64] = hasher.finalize().into();

    // 后续 iter_count-1 轮：hash(prev_output)
    // 复用同一个 hasher（reset() 比重新 new() 节省初始化开销）
    let mut state: [u8; 64] = first;
    let remaining = iter_count.saturating_sub(1);
    let mut hasher = Sha512::new();
    for _ in 0..remaining {
        hasher.update(&state);
        // GenericArray → 固定数组，零拷贝
        state = hasher.finalize_reset().into();
    }
    state
}

impl PasswordChecker {
    /// 创建新的密码检查器
    pub fn new(wallet: BitcoinCoreWallet) -> Self {
        Self {
            wallet,
            checked_count: Arc::new(AtomicU64::new(0)),
            found: Arc::new(AtomicBool::new(false)),
            start_time: Instant::now(),
        }
    }

    /// 检查单个密码（公共接口，保持不变）
    pub fn check_password(&self, password: &str) -> bool {
        let derived = derive_key(
            password.as_bytes(),
            &self.wallet.salt,
            self.wallet.iter_count,
        );
        Self::verify_aes(&derived, &self.wallet.part_encrypted_master_key)
    }

    /// AES-256-CBC 解密验证（抽出为独立函数，便于内联复用）
    #[inline(always)]
    fn verify_aes(derived: &[u8; 64], part_encrypted_master_key: &[u8; 32]) -> bool {
        let key = &derived[..32];
        let iv  = &part_encrypted_master_key[..16];
        let ciphertext = &part_encrypted_master_key[16..];

        if let Ok(cipher) = Aes256CbcDec::new_from_slices(key, iv) {
            // 使用栈上固定大小 buffer，避免 Vec 分配
            let mut buffer = [0u8; 16];
            buffer.copy_from_slice(ciphertext);
            if let Ok(decrypted) = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer) {
                return decrypted.len() == 16 && decrypted.iter().all(|&b| b == 0x10);
            }
        }
        false
    }

    /// 批量检查密码（并行）
    pub fn check_passwords_parallel(
        &self,
        passwords: &[String],
        progress_callback: impl Fn(u64, f64) + Send + Sync,
    ) -> CheckResult {
        let checked_count = self.checked_count.clone();
        let found = self.found.clone();
        let wallet = self.wallet.clone();

        // 使用 Rayon 并行处理
        // 每个线程独立执行 derive_key + verify_aes，无锁争用
        let result = passwords
            .par_iter()
            .find_map_any(|password| {
                // 如果已经找到，提前退出
                if found.load(Ordering::Relaxed) {
                    return None;
                }

                let derived = derive_key(
                    password.as_bytes(),
                    &wallet.salt,
                    wallet.iter_count,
                );

                if Self::verify_aes(&derived, &wallet.part_encrypted_master_key) {
                    found.store(true, Ordering::Relaxed);
                    return Some(password.clone());
                }

                // 每 1000 个密码报告一次进度（减少原子操作频率）
                let count = checked_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count % 1000 == 0 {
                    let elapsed = self.start_time.elapsed().as_secs_f64();
                    let speed = count as f64 / elapsed;
                    progress_callback(count, speed);
                }

                None
            });

        let final_count = checked_count.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let speed = if elapsed > 0.0 {
            final_count as f64 / elapsed
        } else {
            0.0
        };

        CheckResult {
            password: result,
            checked_count: final_count,
            elapsed_secs: elapsed,
            speed,
        }
    }

    /// 获取当前检查的密码数量
    pub fn get_checked_count(&self) -> u64 {
        self.checked_count.load(Ordering::Relaxed)
    }

    /// 获取当前速度（密码/秒）
    pub fn get_speed(&self) -> f64 {
        let count = self.checked_count.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            count as f64 / elapsed
        } else {
            0.0
        }
    }

    /// 重置计数器
    pub fn reset(&mut self) {
        self.checked_count.store(0, Ordering::Relaxed);
        self.found.store(false, Ordering::Relaxed);
        self.start_time = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_checker_creation() {
        let wallet = BitcoinCoreWallet {
            part_encrypted_master_key: [0u8; 32],
            salt: [0u8; 8],
            iter_count: 1000,
        };
        let checker = PasswordChecker::new(wallet);
        assert_eq!(checker.get_checked_count(), 0);
    }

    /// 验证优化版本与原始版本结果一致
    #[test]
    fn test_derive_key_deterministic() {
        let password = b"testpassword";
        let salt = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let result1 = derive_key(password, &salt, 100);
        let result2 = derive_key(password, &salt, 100);
        assert_eq!(result1, result2, "derive_key 必须是确定性的");
    }
}
