use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use memmap2::Mmap;
use rusqlite::Connection;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

/// Bitcoin Core 钱包数据结构
#[derive(Debug, Clone)]
pub struct BitcoinCoreWallet {
    pub part_encrypted_master_key: [u8; 32],
    pub salt: [u8; 8],
    pub iter_count: u32,
}

impl BitcoinCoreWallet {
    /// 从文件加载钱包
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path.as_ref())
            .context("Failed to open wallet file")?;

        // 检查是否是 Berkeley DB 格式
        file.seek(SeekFrom::Start(12))?;
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;

        if magic == [0x62, 0x31, 0x05, 0x00, 0x09, 0x00, 0x00, 0x00] {
            // Berkeley DB 格式
            Self::load_from_bdb(path)
        } else {
            // 尝试 SQLite 格式
            file.seek(SeekFrom::Start(0))?;
            let mut sqlite_magic = [0u8; 16];
            file.read_exact(&mut sqlite_magic)?;
            
            if &sqlite_magic == b"SQLite format 3\0" {
                Self::load_from_sqlite(path)
            } else {
                anyhow::bail!("Unknown wallet format")
            }
        }
    }

    /// 从 Berkeley DB 格式加载
    fn load_from_bdb<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        
        // 读取页面大小
        let page_size = (&mmap[20..24]).read_u32::<LittleEndian>()?;
        let file_size = mmap.len();
        
        // 搜索 mkey
        let target_key = b"\x04mkey\x01\x00\x00\x00";
        
        for page_base in (page_size as usize..file_size).step_by(page_size as usize) {
            if page_base + 26 > file_size {
                break;
            }
            
            let mut cursor = Cursor::new(&mmap[page_base + 20..page_base + 26]);
            let item_count = cursor.read_u16::<LittleEndian>()?;
            let first_item_pos = cursor.read_u16::<LittleEndian>()?;
            let btree_level = cursor.read_u8()?;
            let page_type = cursor.read_u8()?;
            
            // 只处理 btree 叶子页
            if page_type != 5 || btree_level != 1 {
                continue;
            }
            
            let mut pos = Self::align_32bits(page_base + first_item_pos as usize);
            
            for i in 0..item_count {
                if pos + 3 > file_size {
                    break;
                }
                
                let mut cursor = Cursor::new(&mmap[pos..pos + 3]);
                let item_len = cursor.read_u16::<LittleEndian>()? as usize;
                let item_type = cursor.read_u8()?;
                
                if (item_type & !0x80) == 1 && item_type == 1 {
                    if i % 2 == 0 {
                        // 这是一个值，记录位置
                        let value_pos = pos + 3;
                        let value_len = item_len;
                        
                        // 检查下一个项（键）
                        let next_pos = Self::align_32bits(pos + 3 + item_len);
                        if next_pos + 3 + 9 <= file_size {
                            let mut cursor = Cursor::new(&mmap[next_pos..next_pos + 3]);
                            let next_len = cursor.read_u16::<LittleEndian>()? as usize;
                            let next_type = cursor.read_u8()?;
                            
                            if next_type == 1 && next_len == 9 {
                                let key = &mmap[next_pos + 3..next_pos + 3 + 9];
                                if key == target_key {
                                    // 找到了！解析 mkey
                                    return Self::parse_mkey(&mmap[value_pos..value_pos + value_len]);
                                }
                            }
                        }
                    }
                    pos = Self::align_32bits(pos + 3 + item_len);
                } else {
                    pos += 12;
                }
            }
        }
        
        anyhow::bail!("Master key not found in Berkeley DB wallet")
    }

    /// 从 SQLite 格式加载
    fn load_from_sqlite<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        
        let mut stmt = conn.prepare("SELECT key, value FROM main")?;
        let mut rows = stmt.query([])?;
        
        while let Some(row) = rows.next()? {
            let key: Vec<u8> = row.get(0)?;
            let value: Vec<u8> = row.get(1)?;
            
            if key.windows(9).any(|w| w == b"\x04mkey\x01\x00\x00\x00") {
                return Self::parse_mkey(&value);
            }
        }
        
        anyhow::bail!("Master key not found in SQLite wallet")
    }

    /// 解析 mkey 数据
    fn parse_mkey(data: &[u8]) -> Result<Self> {
        if data.len() < 62 {
            anyhow::bail!("Invalid mkey data length: {} (expected at least 62)", data.len());
        }
        
        let mut offset = 0;
        
        // 读取加密的主密钥 (49p = Pascal string)
        let encrypted_key_len = data[offset] as usize;
        offset += 1;
        
        if encrypted_key_len != 48 {
            anyhow::bail!("Unexpected encrypted key length: {} (expected 48)", encrypted_key_len);
        }
        
        if offset + encrypted_key_len > data.len() {
            anyhow::bail!("Data too short for encrypted key");
        }
        
        let encrypted_master_key = &data[offset..offset + encrypted_key_len];
        offset += encrypted_key_len;
        
        // 只需要最后 32 字节
        let part_encrypted_master_key: [u8; 32] = 
            encrypted_master_key[encrypted_key_len - 32..].try_into()?;
        
        // 读取 salt (9p = Pascal string)
        if offset >= data.len() {
            anyhow::bail!("Data too short for salt length");
        }
        
        let salt_len = data[offset] as usize;
        offset += 1;
        
        if salt_len != 8 {
            anyhow::bail!("Unexpected salt length: {} (expected 8)", salt_len);
        }
        
        if offset + salt_len > data.len() {
            anyhow::bail!("Data too short for salt");
        }
        
        let salt: [u8; 8] = data[offset..offset + salt_len].try_into()?;
        offset += salt_len;
        
        // 读取 method (4 bytes)
        if offset + 4 > data.len() {
            anyhow::bail!("Data too short for method");
        }
        
        let mut cursor = Cursor::new(&data[offset..offset + 4]);
        let method = cursor.read_u32::<LittleEndian>()?;
        offset += 4;
        
        if method != 0 {
            anyhow::bail!("Unsupported key derivation method: {}", method);
        }
        
        // 读取 iter_count (4 bytes)
        if offset + 4 > data.len() {
            anyhow::bail!("Data too short for iter_count");
        }
        
        let mut cursor = Cursor::new(&data[offset..offset + 4]);
        let iter_count = cursor.read_u32::<LittleEndian>()?;
        
        Ok(Self {
            part_encrypted_master_key,
            salt,
            iter_count,
        })
    }

    /// 32位对齐
    fn align_32bits(i: usize) -> usize {
        let m = i % 4;
        if m == 0 { i } else { i + 4 - m }
    }

    /// 获取难度信息
    pub fn difficulty_info(&self) -> String {
        // 手动添加千位分隔符
        let count_str = self.iter_count.to_string();
        let mut result = String::new();
        for (i, c) in count_str.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                result.push(',');
            }
            result.push(c);
        }
        format!("{} SHA-512 iterations", result.chars().rev().collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_32bits() {
        assert_eq!(BitcoinCoreWallet::align_32bits(0), 0);
        assert_eq!(BitcoinCoreWallet::align_32bits(1), 4);
        assert_eq!(BitcoinCoreWallet::align_32bits(4), 4);
        assert_eq!(BitcoinCoreWallet::align_32bits(5), 8);
    }
}
