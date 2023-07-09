use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, Nonce, OsRng};
use aes_gcm::aes::Aes256;
use aes_gcm::{AeadCore, Aes256Gcm, AesGcm, Key, KeyInit};
use argon2::password_hash::{Output, Salt, SaltString};
use argon2::{password_hash, Argon2, PasswordHasher};
use serde::ser::Error as _;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::fs::{read_to_string, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::slice::{Iter, IterMut};
use std::str::FromStr;
use std::string::FromUtf8Error;
use std::time::SystemTime;

#[derive(Debug)]
pub enum Error {
    JsonError(serde_json::Error),
    IoError(std::io::Error),
    HashError(password_hash::Error),
    NoHash,
    EncryptionError(aes_gcm::Error),
    DecryptionError(aes_gcm::Error),
    Utf8Error(FromUtf8Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonError(error) => <serde_json::Error as Display>::fmt(error, f),
            Self::IoError(error) => <std::io::Error as Display>::fmt(error, f),
            Self::HashError(error) => <password_hash::Error as Display>::fmt(error, f),
            Self::NoHash => write!(f, "could not generate hash"),
            Self::EncryptionError(error) | Self::DecryptionError(error) => {
                <aes_gcm::Error as Display>::fmt(error, f)
            }
            Self::Utf8Error(error) => <FromUtf8Error as Display>::fmt(error, f),
        }
    }
}

trait Codec {
    /// Decrypts a cipher text using a password
    /// # Errors
    /// Returns an [`passwds::Error`] on errors.
    fn decrypt(&self, cipher_text: &[u8], password: &str) -> Result<Vec<u8>, Error> {
        self.cipher(password).and_then(|cipher| {
            cipher
                .decrypt(&self.nonce(), cipher_text)
                .map_err(Error::DecryptionError)
        })
    }

    /// Encrypt plain data using a password
    /// # Errors
    /// Returns an [`passwds::Error`] on errors.
    fn encrypt(&self, plain: &[u8], password: &str) -> Result<Vec<u8>, Error> {
        self.cipher(password).and_then(|cipher| {
            cipher
                .encrypt(&self.nonce(), plain)
                .map_err(Error::EncryptionError)
        })
    }

    /// Returns the AES cipher for the given password
    /// # Errors
    /// Returns an [`passwds::Error`] on errors.
    fn cipher(&self, password: &str) -> Result<Aes256Gcm, Error> {
        self.key(password)
            .map(|key| Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes())))
    }

    /// Returns the encryption key for AES derived with Argon2
    /// # Errors
    /// Returns an [`passwds::Error`] on errors.
    fn key(&self, password: &str) -> Result<Output, Error> {
        Argon2::default()
            .hash_password(password.as_bytes(), self.salt()?)
            .map_err(Error::HashError)?
            .hash
            .ok_or(Error::NoHash)
    }

    fn nonce(&self) -> Nonce<AesGcm<Aes256, U12>>;

    /// Returns the parsed Salt for Argon2
    /// # Errors
    /// Returns an [`passwds::Error`] on parsing errors.
    fn salt(&self) -> Result<Salt, Error>;
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Keystore {
    salt: String,
    nonce: Vec<u8>,
    entries: Vec<u8>,
}

impl Keystore {
    /// Unlocks the keystore
    /// # Errors
    /// Returns an [`passwds::Error`] on parsing errors.
    pub fn unlock(&self, password: &str) -> Result<UnlockedKeystore, Error> {
        self.decrypt(self.entries.as_slice(), password)
            .and_then(|plain| String::from_utf8(plain).map_err(Error::Utf8Error))
            .and_then(|json| {
                serde_json::from_str::<Vec<Entry>>(json.as_str()).map_err(Error::JsonError)
            })
            .map(|entries| UnlockedKeystore {
                salt: self.salt.clone(),
                nonce: self.nonce(),
                entries,
            })
    }

    /// Loads the keystore from a file
    /// # Errors
    /// Returns an [`passwds::Error`] on errors.
    pub fn load(filename: impl AsRef<Path>) -> Result<Self, Error> {
        Self::try_from(read_to_string(filename.as_ref()).map_err(Error::IoError)?)
            .map_err(Error::JsonError)
    }

    /// Saves the keystore to a file
    /// # Errors
    /// Returns an [`passwds::Error`] on errors.
    pub fn save(&self, filename: impl AsRef<Path>) -> Result<(), Error> {
        serde_json::to_string(self)
            .map_err(Error::JsonError)
            .and_then(|json| {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(filename.as_ref())
                    .and_then(|mut file| file.write_all(json.as_bytes()))
                    .map_err(Error::IoError)
                    .map(drop)
            })
    }
}

impl Codec for Keystore {
    fn nonce(&self) -> Nonce<AesGcm<Aes256, U12>> {
        *Nonce::<AesGcm<Aes256, U12>>::from_slice(self.nonce.as_slice())
    }

    fn salt(&self) -> Result<Salt, Error> {
        Salt::from_b64(self.salt.as_str()).map_err(Error::HashError)
    }
}

impl TryFrom<File> for Keystore {
    type Error = Error;

    fn try_from(mut file: File) -> Result<Self, Self::Error> {
        let mut buf = String::new();
        file.read_to_string(&mut buf).map_err(Error::IoError)?;
        Self::try_from(buf).map_err(Error::JsonError)
    }
}

impl FromStr for Keystore {
    type Err = serde_json::Error;

    fn from_str(json: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(json)
    }
}

impl TryFrom<String> for Keystore {
    type Error = serde_json::Error;

    fn try_from(json: String) -> Result<Self, Self::Error> {
        Self::from_str(json.as_str())
    }
}

#[derive(Debug)]
pub struct UnlockedKeystore {
    salt: String,
    nonce: Nonce<AesGcm<Aes256, U12>>,
    entries: Vec<Entry>,
}

impl UnlockedKeystore {
    pub fn entries(&self) -> Iter<'_, Entry> {
        self.entries.iter()
    }

    pub fn entries_mut(&mut self) -> IterMut<'_, Entry> {
        self.entries.iter_mut()
    }

    /// Locks the keystore
    /// # Errors
    /// Returns an [`passwds::Error`] on parsing errors.
    pub fn lock(self, password: &str) -> Result<Keystore, Error> {
        serde_json::to_string::<Vec<Entry>>(self.entries.as_ref())
            .map_err(Error::JsonError)
            .and_then(|json| self.encrypt(json.as_bytes(), password))
            .map(|cipher_text| Keystore {
                salt: self.salt.to_string(),
                nonce: Vec::from(self.nonce.as_slice()),
                entries: cipher_text,
            })
    }

    pub fn add(&mut self, password: &str, login: Option<&str>, url: Option<&str>) {
        self.entries.push(Entry::new(password, login, url));
    }
}

impl Codec for UnlockedKeystore {
    fn nonce(&self) -> Nonce<AesGcm<Aes256, U12>> {
        self.nonce
    }

    fn salt(&self) -> Result<Salt, Error> {
        Salt::from_b64(self.salt.as_str()).map_err(Error::HashError)
    }
}

impl Default for UnlockedKeystore {
    fn default() -> Self {
        Self {
            salt: SaltString::generate(&mut OsRng).as_salt().to_string(),
            nonce: Aes256Gcm::generate_nonce(&mut OsRng),
            entries: Vec::new(),
        }
    }
}

impl Display for UnlockedKeystore {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string_pretty::<Vec<Entry>>(self.entries.as_ref())
                .map_err(|error| std::fmt::Error::custom(error.to_string()))?
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Entry {
    password: String,
    created: SystemTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_change: Option<SystemTime>,
}

impl Entry {
    pub fn new(password: &str, login: Option<&str>, url: Option<&str>) -> Self {
        Self {
            password: password.to_string(),
            login: login.map(ToString::to_string),
            url: url.map(ToString::to_string),
            created: SystemTime::now(),
            last_change: None,
        }
    }
}
