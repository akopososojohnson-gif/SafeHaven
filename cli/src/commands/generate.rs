use anyhow::Result;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*-_+=~";

pub fn password(length: usize, symbols: bool) -> Result<()> {
    let mut charset = Vec::new();
    charset.extend_from_slice(LOWER);
    charset.extend_from_slice(UPPER);
    charset.extend_from_slice(DIGITS);
    if symbols {
        charset.extend_from_slice(SYMBOLS);
    }

    let mut buf = vec![0u8; length];
    crypto::cipher::fill_random(&mut buf);

    let password: String = buf
        .iter()
        .map(|b| charset[*b as usize % charset.len()] as char)
        .collect();

    println!("{}", password);
    Ok(())
}
