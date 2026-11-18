//! Bounded raw credential snapshot. PIN, pairing and OTP never enter exports.
#[cfg(target_os = "none")]
use super::Storage;
pub use crate::init::snapshot::{LIMIT, allowed, validate};
#[cfg(target_os = "none")]
impl Storage<'_> {
    pub(crate) async fn snapshot(
        &mut self,
        key: &[u8; 32],
        out: &mut [u8],
    ) -> Result<usize, super::Error> {
        out[..8].copy_from_slice(b"DOOHBAK1");
        out[8..40].copy_from_slice(key);
        // Iterate history, fetch latest values, and emit each key only once.
        let mut keys = [0u32; 256];
        let mut count = 0;
        let mut items = self.map.fetch_all_items(&mut self.buffer).await?;
        while let Some((key, _)) = items.next::<&[u8]>(&mut self.buffer).await? {
            if allowed(key) && !keys[..count].contains(&key) {
                if count == keys.len() {
                    return Err(super::Error::ValueTooLarge);
                }
                keys[count] = key;
                count += 1;
            }
        }
        let mut p = 40;
        for key in &keys[..count] {
            let mut value = zeroize::Zeroizing::new([0; 1024]);
            let n = self
                .read(*key, &mut value[..])
                .await?
                .ok_or(super::Error::InvalidMetadata)?;
            if p + 6 + n > out.len() {
                return Err(super::Error::ValueTooLarge);
            }
            out[p..p + 4].copy_from_slice(&key.to_le_bytes());
            out[p + 4..p + 6].copy_from_slice(&(n as u16).to_le_bytes());
            out[p + 6..p + 6 + n].copy_from_slice(&value[..n]);
            p += 6 + n;
        }
        Ok(p)
    }
}
