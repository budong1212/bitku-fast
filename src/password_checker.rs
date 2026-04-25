use crate::wallet::BitcoinCoreWallet;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use crossbeam::channel::Receiver;
use rayon::prelude::*;
use sha2::{Digest, Sha512};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// 密码检查器
pub struct PasswordChecker {
    pub wallet: BitcoinCoreWallet,
    pub checked_count: Arc<AtomicU64>,
    pub found: Arc<AtomicBool>,
    pub cancelled: Arc<AtomicBool>,
    pub start_time: Instant,
}

/// 检查结果
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub password: Option<String>,
    pub checked_count: u64,
    pub elapsed_secs: f64,
    pub speed: f64,
    pub cancelled: bool,
}

/// 核心 KDF：对单个密码执行 SHA-512 迭代派生密钥
///
/// 优化要点：
/// 1. `[u8; 64]` 固定大小栈数组替代 `Vec<u8>`，完全消除堆分配
/// 2. 循环内复用同一个 `Sha512` 实例（reset 比 new 快）
/// 3. 第一次迭代输入 = password || salt（栈上拼接）
/// 4. 借助 `.cargo/config.toml` 的 `target-cpu=native` + `sha2 asm` feature
///    自动启用 SHA-NI / AVX2 硬件加速
#[inline(always)]
fn derive_key(password_bytes: &[u8], salt: &[u8; 8], iter_count: u32) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(password_bytes);
    hasher.update(salt);
    let first: [u8; 64] = hasher.finalize().into();

    let mut state: [u8; 64] = first;
    let remaining = iter_count.saturating_sub(1);
    let mut hasher = Sha512::new();
    for _ in 0..remaining {
        hasher.update(&state);
        state = hasher.finalize_reset().into();
    }
    state
}

impl PasswordChecker {
    pub fn new(wallet: BitcoinCoreWallet) -> Self {
        Self {
            wallet,
            checked_count: Arc::new(AtomicU64::new(0)),
            found: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            start_time: Instant::now(),
        }
    }

    /// 检查单个密码
    pub fn check_password(&self, password: &str) -> bool {
        let derived = derive_key(
            password.as_bytes(),
            &self.wallet.salt,
            self.wallet.iter_count,
        );
        Self::verify_aes(&derived, &self.wallet.part_encrypted_master_key)
    }

    /// AES-256-CBC 解密验证
    #[inline(always)]
    fn verify_aes(derived: &[u8; 64], part_encrypted_master_key: &[u8; 32]) -> bool {
        let key = &derived[..32];
        let iv = &part_encrypted_master_key[..16];
        let ciphertext = &part_encrypted_master_key[16..];

        if let Ok(cipher) = Aes256CbcDec::new_from_slices(key, iv) {
            let mut buffer = [0u8; 16];
            buffer.copy_from_slice(ciphertext);
            if let Ok(decrypted) = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer) {
                return decrypted.len() == 16 && decrypted.iter().all(|&b| b == 0x10);
            }
        }
        false
    }

    /// 从 channel 接收批次，流水线并行检查。
    /// IO 线程（调用方）负责读文件并按批次发送，本函数在 Rayon 线程池中消费。
    /// 支持外部取消信号 `cancelled`。
    pub fn check_passwords_from_channel(
        &self,
        rx: Receiver<Vec<String>>,
        progress_callback: impl Fn(u64, f64) + Send + Sync,
    ) -> CheckResult {
        let checked_count = self.checked_count.clone();
        let found = self.found.clone();
        let cancelled = self.cancelled.clone();
        let wallet = self.wallet.clone();
        let start = self.start_time;

        let mut result_password: Option<String> = None;

        'outer: for batch in rx {
            if found.load(Ordering::Relaxed) || cancelled.load(Ordering::Relaxed) {
                break;
            }

            let found2 = found.clone();
            let cancelled2 = cancelled.clone();
            let wallet2 = wallet.clone();
            let checked2 = checked_count.clone();

            let hit = batch.par_iter().find_map_any(|password| {
                if found2.load(Ordering::Relaxed) || cancelled2.load(Ordering::Relaxed) {
                    return None;
                }

                let derived = derive_key(
                    password.as_bytes(),
                    &wallet2.salt,
                    wallet2.iter_count,
                );

                let ok = Self::verify_aes(&derived, &wallet2.part_encrypted_master_key);

                // 每个密码都计入（成功或失败）
                let count = checked2.fetch_add(1, Ordering::Relaxed) + 1;
                if count % 500 == 0 {
                    let elapsed = start.elapsed().as_secs_f64();
                    let speed = count as f64 / elapsed.max(1e-9);
                    progress_callback(count, speed);
                }

                if ok {
                    found2.store(true, Ordering::Relaxed);
                    Some(password.clone())
                } else {
                    None
                }
            });

            if let Some(pw) = hit {
                result_password = Some(pw);
                break 'outer;
            }
        }

        let final_count = checked_count.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let speed = final_count as f64 / elapsed.max(1e-9);

        CheckResult {
            password: result_password,
            checked_count: final_count,
            elapsed_secs: elapsed,
            speed,
            cancelled: self.cancelled.load(Ordering::Relaxed),
        }
    }

    /// 取消正在运行的任务
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn get_checked_count(&self) -> u64 {
        self.checked_count.load(Ordering::Relaxed)
    }

    pub fn get_speed(&self) -> f64 {
        let count = self.checked_count.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        count as f64 / elapsed.max(1e-9)
    }

    pub fn reset(&mut self) {
        self.checked_count.store(0, Ordering::Relaxed);
        self.found.store(false, Ordering::Relaxed);
        self.cancelled.store(false, Ordering::Relaxed);
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

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"testpassword";
        let salt = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let r1 = derive_key(password, &salt, 100);
        let r2 = derive_key(password, &salt, 100);
        assert_eq!(r1, r2, "derive_key 必须是确定性的");
    }

    #[test]
    fn test_cancel() {
        let wallet = BitcoinCoreWallet {
            part_encrypted_master_key: [0u8; 32],
            salt: [0u8; 8],
            iter_count: 1,
        };
        let checker = PasswordChecker::new(wallet);
        checker.cancel();
        assert!(checker.cancelled.load(std::sync::atomic::Ordering::Relaxed));
    }
}
