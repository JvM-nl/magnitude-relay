//! Where the account key and the issued certificate live: `<data dir>/tls/`.
//!
//! ```text
//! account.key   the ACME account's private key (PKCS#8, PEM)
//! cert.pem      the issued chain, leaf first
//! key.pem       the certificate's private key
//! directory     the ACME directory URL that issued cert.pem
//! ```
//!
//! Everything is written atomically (temp file, fsync, rename, fsync of the folder)
//! and readable by the relay's user only, so a crash leaves the old file or the
//! new one, never half of one.

use crate::pem;
use crate::x509::EcKey;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The `tls` folder of a data directory.
#[derive(Debug, Clone)]
pub struct Dir {
    path: PathBuf,
}

/// A saved certificate, as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub chain_pem: String,
    pub key_pem: String,
    /// The directory that issued it, when recorded.
    pub directory: Option<String>,
}

/// Writes `data` to `path` so that readers see the old contents or the new, never a
/// mixture, and so that the new contents are on disk before the old are gone. The
/// file is private to the owner.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let tmp = parent.join(format!(".{}.tmp-{}", name.to_string_lossy(), std::process::id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        // The rename itself must survive a crash too. Not every platform lets a
        // folder be opened for this; the data is safe either way.
        if let Ok(d) = File::open(parent) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn read_text(path: &Path) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

impl Dir {
    /// Creates `<data>/tls` (private to the owner) if it is not there.
    pub fn open(data: &Path) -> io::Result<Dir> {
        let path = data.join("tls");
        fs::create_dir_all(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Dir { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn cert_path(&self) -> PathBuf {
        self.path.join("cert.pem")
    }

    /// The account key, made (and saved) on first use. A file that cannot be read as a
    /// key is moved aside rather than overwritten, and a new account started.
    pub fn account_key(&self) -> Result<EcKey, String> {
        let file = self.path.join("account.key");
        let existing = read_text(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        if let Some(text) = existing {
            match pem::private_key(&text).and_then(|b| EcKey::from_pkcs8(&b.der)) {
                Ok(k) => return Ok(k),
                Err(e) => {
                    let aside = self.path.join(format!("account.key.unreadable-{}", crate::time::now()));
                    eprintln!("tls: {} cannot be used ({e}); moving it to {} and starting a new account", file.display(), aside.display());
                    fs::rename(&file, &aside).map_err(|e| format!("{}: {e}", file.display()))?;
                }
            }
        }
        let key = EcKey::generate()?;
        write_atomic(&file, pem::encode("PRIVATE KEY", key.pkcs8()).as_bytes()).map_err(|e| format!("{}: {e}", file.display()))?;
        Ok(key)
    }

    /// The saved certificate, if both of its files are there.
    pub fn load(&self) -> Result<Option<Saved>, String> {
        let read = |name: &str| read_text(&self.path.join(name)).map_err(|e| format!("{}: {e}", self.path.join(name).display()));
        let (Some(chain_pem), Some(key_pem)) = (read("cert.pem")?, read("key.pem")?) else { return Ok(None) };
        let directory = read("directory")?.map(|d| d.trim().to_string()).filter(|d| !d.is_empty());
        Ok(Some(Saved { chain_pem, key_pem, directory }))
    }

    /// Saves a certificate. The key goes first: a crash between the two files leaves
    /// a new key beside an old certificate, which fails to load (the pair does not
    /// match) and is simply re-issued, where the other order would pair a new
    /// certificate with a key it cannot sign for.
    pub fn save(&self, saved: &Saved) -> io::Result<()> {
        write_atomic(&self.path.join("key.pem"), saved.key_pem.as_bytes())?;
        write_atomic(&self.path.join("cert.pem"), saved.chain_pem.as_bytes())?;
        match &saved.directory {
            Some(d) => write_atomic(&self.path.join("directory"), format!("{d}\n").as_bytes()),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("relay-tls-store-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn atomic_write_replaces_and_leaves_nothing_behind() {
        let d = temp("atomic");
        let f = d.join("x.pem");
        write_atomic(&f, b"one").unwrap();
        write_atomic(&f, b"two, longer").unwrap();
        write_atomic(&f, b"3").unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"3");
        let names: Vec<_> = fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names, ["x.pem"], "no temporary files remain");
        #[cfg(unix)]
        assert_eq!(mode(&f), 0o600);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn failed_write_cleans_up() {
        let d = temp("failed");
        // The target is a folder, so the rename fails.
        fs::create_dir(d.join("x.pem")).unwrap();
        assert!(write_atomic(&d.join("x.pem"), b"data").is_err());
        let names: Vec<_> = fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names, ["x.pem"]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_folder_and_files_are_private() {
        let data = temp("private");
        let dir = Dir::open(&data).unwrap();
        #[cfg(unix)]
        assert_eq!(mode(dir.path()), 0o700);
        dir.account_key().unwrap();
        dir.save(&Saved { chain_pem: "c".into(), key_pem: "k".into(), directory: Some("https://ca/dir".into()) }).unwrap();
        #[cfg(unix)]
        for f in ["account.key", "cert.pem", "key.pem", "directory"] {
            assert_eq!(mode(&dir.path().join(f)), 0o600, "{f}");
        }
        fs::remove_dir_all(&data).unwrap();
    }

    #[test]
    fn account_key_is_made_once_and_kept() {
        let data = temp("account");
        let dir = Dir::open(&data).unwrap();
        let a = dir.account_key().unwrap();
        let b = dir.account_key().unwrap();
        assert_eq!(a.public_point(), b.public_point());
        assert_eq!(Dir::open(&data).unwrap().account_key().unwrap().public_point(), a.public_point(), "a restart finds it");
        fs::remove_dir_all(&data).unwrap();
    }

    #[test]
    fn an_unreadable_account_key_is_kept_aside() {
        let data = temp("badkey");
        let dir = Dir::open(&data).unwrap();
        fs::write(dir.path().join("account.key"), "garbage").unwrap();
        let k = dir.account_key().unwrap();
        let aside: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("account.key.unreadable-"))
            .collect();
        assert_eq!(aside.len(), 1);
        assert_eq!(fs::read_to_string(dir.path().join(&aside[0])).unwrap(), "garbage");
        assert_eq!(dir.account_key().unwrap().public_point(), k.public_point());
        fs::remove_dir_all(&data).unwrap();
    }

    #[test]
    fn certificates_save_and_load() {
        let data = temp("cert");
        let dir = Dir::open(&data).unwrap();
        assert_eq!(dir.load().unwrap(), None);
        let saved = Saved { chain_pem: "chain".into(), key_pem: "key".into(), directory: Some("https://ca.example/dir".into()) };
        dir.save(&saved).unwrap();
        assert_eq!(dir.load().unwrap(), Some(saved));
        // A certificate without its key is not a certificate.
        fs::remove_file(dir.path().join("key.pem")).unwrap();
        assert_eq!(dir.load().unwrap(), None);
        fs::remove_dir_all(&data).unwrap();
    }

    #[test]
    fn a_missing_directory_record_is_tolerated() {
        let data = temp("nodir");
        let dir = Dir::open(&data).unwrap();
        dir.save(&Saved { chain_pem: "c".into(), key_pem: "k".into(), directory: None }).unwrap();
        assert_eq!(dir.load().unwrap().unwrap().directory, None);
        fs::remove_dir_all(&data).unwrap();
    }
}
