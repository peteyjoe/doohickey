//! Credential backup wire validation.
pub const LIMIT: usize = 32768;
pub fn allowed(key: u32) -> bool {
    key & 0xff00_0000 == 0x0100_0000 || key & 0xffff_ff00 == 0x0300_0000
}
#[derive(Debug)]
pub struct InvalidSnapshot;
pub fn validate(bytes: &[u8]) -> Result<(), InvalidSnapshot> {
    if bytes.len() < 40 || &bytes[..8] != b"DOOHBAK1" || bytes.len() > LIMIT {
        return Err(InvalidSnapshot);
    }
    let master = doohickey_crypto::secrets::MasterKey::from_bytes(zeroize::Zeroizing::new(
        bytes[8..40].try_into().unwrap(),
    ));
    let cipher = doohickey_crypto::secrets::SecretBox::from_master_key(&master);
    let mut p = 40;
    while p < bytes.len() {
        if p + 6 > bytes.len() {
            return Err(InvalidSnapshot);
        }
        let key = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
        let n = u16::from_le_bytes(bytes[p + 4..p + 6].try_into().unwrap()) as usize;
        if !allowed(key) || n > 1024 || n == 0 || p + 6 + n > bytes.len() {
            return Err(InvalidSnapshot);
        }
        let mut aad = [0; 33];
        aad[..27].copy_from_slice(b"DOOHICKEY encrypted storage");
        aad[27] = 1;
        aad[28] = if key & 0xff00_0000 == 0x01000000 {
            1
        } else {
            3
        };
        aad[29..].copy_from_slice(&key.to_le_bytes());
        let mut plain = zeroize::Zeroizing::new([0; 983]);
        let size = cipher
            .open(&aad, &bytes[p + 6..p + 6 + n], &mut plain[..])
            .map_err(|_| InvalidSnapshot)?;
        if aad[28] == 1 {
            if !((size == 202 && &plain[..8] == b"DOOHCR01")
                || (size == 660 && &plain[..8] == b"DOOHCR02")
                || (size == 727 && &plain[..8] == b"DOOHCR03"))
                || plain[8] > 2
                || plain[17..21] != key.to_le_bytes()
            {
                return Err(InvalidSnapshot);
            }
            if &plain[9..17] != b"DOOHCID1" {
                return Err(InvalidSnapshot);
            }
            let id_key = zeroize::Zeroizing::new(doohickey_crypto::ctap::hmac_sha256(
                &bytes[8..40],
                b"DOOHICKEY credential id v1",
            ));
            let mut id_message = [0; 60];
            id_message[..28].copy_from_slice(&plain[9..37]);
            id_message[28..].copy_from_slice(&plain[69..101]);
            if doohickey_crypto::ctap::hmac_sha256(&id_key[..], &id_message) != plain[37..69] {
                return Err(InvalidSnapshot);
            }
            let resident = size == 660 || size == 727 && plain[726] == 1;
            if (plain[8] == 2) != (resident && plain[8] != 0) {
                return Err(InvalidSnapshot);
            }
            if size == 727
                && (!(1..=3).contains(&plain[660])
                    || plain[661] > 1
                    || plain[726] > 1
                    || plain[661] == 0 && plain[662..726].iter().any(|b| *b != 0))
            {
                return Err(InvalidSnapshot);
            }
            if plain[8] != 0 {
                if !(1..=64).contains(&plain[101]) {
                    return Err(InvalidSnapshot);
                }
                if resident {
                    for (len, start) in [(202, 203), (267, 268), (587, 588)] {
                        let n = plain[len] as usize;
                        if n > 64 || core::str::from_utf8(&plain[start..start + n]).is_err() {
                            return Err(InvalidSnapshot);
                        }
                    }
                    let n = u16::from_le_bytes(plain[332..334].try_into().unwrap()) as usize;
                    if n == 0
                        || n > 253
                        || core::str::from_utf8(&plain[334..334 + n]).is_err()
                        || doohickey_crypto::ctap::sha256(&plain[334..334 + n]) != plain[69..101]
                    {
                        return Err(InvalidSnapshot);
                    }
                }
                doohickey_crypto::ctap::Es256Key::from_bytes(plain[166..198].try_into().unwrap())
                    .map_err(|_| InvalidSnapshot)?;
            }
        } else if size != 865 || &plain[..8] != b"DOOHRK01" || plain[24] > 14 {
            return Err(InvalidSnapshot);
        }
        if aad[28] == 3 {
            if plain[25 + usize::from(plain[24]) * 60..size]
                .iter()
                .any(|b| *b != 0)
            {
                return Err(InvalidSnapshot);
            }
            for id in plain[25..25 + usize::from(plain[24]) * 60]
                .as_chunks::<60>()
                .0
            {
                let mut cursor = 40;
                let mut found = false;
                while cursor < bytes.len() {
                    if cursor + 6 > bytes.len() {
                        return Err(InvalidSnapshot);
                    }
                    let address = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                    let length =
                        u16::from_le_bytes(bytes[cursor + 4..cursor + 6].try_into().unwrap())
                            as usize;
                    if cursor + 6 + length > bytes.len() {
                        return Err(InvalidSnapshot);
                    }
                    if address.to_le_bytes() == id[8..12] {
                        let mut context = aad;
                        context[28] = 1;
                        context[29..].copy_from_slice(&address.to_le_bytes());
                        let mut record = zeroize::Zeroizing::new([0; 983]);
                        let size = cipher
                            .open(
                                &context,
                                &bytes[cursor + 6..cursor + 6 + length],
                                &mut record[..],
                            )
                            .map_err(|_| InvalidSnapshot)?;
                        if size < 202
                            || record[8] != 2
                            || record[9..69] != *id
                            || record[69] != key as u8
                        {
                            return Err(InvalidSnapshot);
                        }
                        found = true;
                        break;
                    }
                    cursor += 6 + length;
                }
                if !found {
                    return Err(InvalidSnapshot);
                }
            }
        }
        let mut previous = 40;
        while previous < p {
            if bytes[previous..previous + 4] == bytes[p..p + 4] {
                return Err(InvalidSnapshot);
            }
            previous +=
                6 + u16::from_le_bytes(bytes[previous + 4..previous + 6].try_into().unwrap())
                    as usize;
        }
        p += 6 + n;
    }
    Ok(())
}
