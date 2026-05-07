use anyhow::Result;
use std::fs;

const SERVICE: &str = "safehaven-cli";
const USERNAME: &str = "session";

pub fn store_token(token: &str) -> Result<()> {
    // Try keyring first, fall back to file
    match keyring::Entry::new(SERVICE, USERNAME) {
        Ok(entry) => {
            if let Err(e) = entry.set_password(token) {
                eprintln!("Keyring store failed ({}), falling back to file.", e);
                store_token_file(token)?;
            }
        }
        Err(e) => {
            eprintln!("Keyring unavailable ({}), falling back to file.", e);
            store_token_file(token)?;
        }
    }
    Ok(())
}

pub fn get_token() -> Result<Option<String>> {
    match keyring::Entry::new(SERVICE, USERNAME) {
        Ok(entry) => match entry.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => {
                eprintln!("Keyring read failed ({}), trying file fallback.", e);
                get_token_file()
            }
        },
        Err(e) => {
            eprintln!("Keyring unavailable ({}), trying file fallback.", e);
            get_token_file()
        }
    }
}

pub fn delete_token() -> Result<()> {
    match keyring::Entry::new(SERVICE, USERNAME) {
        Ok(entry) => {
            let _ = entry.delete_credential();
        }
        Err(_) => {}
    }
    let _ = fs::remove_file(crate::config::token_path());
    Ok(())
}

fn store_token_file(token: &str) -> Result<()> {
    let path = crate::config::token_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn get_token_file() -> Result<Option<String>> {
    let path = crate::config::token_path();
    match fs::read_to_string(&path) {
        Ok(token) => Ok(Some(token.trim().to_string())),
        Err(_) => Ok(None),
    }
}
