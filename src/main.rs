use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes256;
use base64::{Engine, engine::general_purpose};
use cipher::generic_array::GenericArray;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, block_padding::Pkcs7};
use data_encoding::BASE32_NOPAD;
use ecb::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use urlencoding::encode;

type Aes256EcbEnc = Encryptor<Aes256>;
type Aes256EcbDec = Decryptor<Aes256>;
type HmacSha1 = Hmac<Sha1>;

const MASTER_KEY: [u8; 32] = [
    0x1d, 0x6d, 0x23, 0x43, 0x65, 0x51, 0x56, 0x37, 0x50, 0x04, 0x55, 0x4c, 0x56, 0x14, 0x6e, 0x43,
    0x7b, 0x5c, 0x59, 0x6f, 0x57, 0x02, 0x04, 0x6d, 0x5c, 0x26, 0x00, 0x75, 0x58, 0x43, 0x56, 0x79,
];

/// Encrypt arbitrary secret bytes under a 32-byte AES key, return base64.
pub fn encrypt_secret(key_bytes: &[u8; 32], secret_bytes: &[u8]) -> String {
    let key = GenericArray::clone_from_slice(key_bytes);
    let encryptor = Aes256EcbEnc::new(&key);
    let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(secret_bytes);
    general_purpose::STANDARD.encode(&ciphertext)
}

/// Decrypt base64 blob into raw secret bytes.
pub fn decrypt_secret(key_bytes: &[u8; 32], blob_base64: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let ciphertext = general_purpose::STANDARD.decode(blob_base64)?;
    let key = GenericArray::clone_from_slice(key_bytes);
    let decryptor = Aes256EcbDec::new(&key);
    let decrypted = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .map_err(|e| -> Box<dyn Error> {
            Box::<dyn Error>::from(format!("Unpadding failed: {:?}", e))
        })?;
    Ok(decrypted)
}

/// Google Auth–compatible TOTP helper.
/// - 6 digits
/// - HMAC-SHA1
/// - 30-second period
#[derive(Debug, Clone)]
pub struct TOTP {
    /// Secret as raw bytes.
    secret: Vec<u8>,
    /// Displayed "issuer" (e.g., your app name).
    issuer: String,
    /// Displayed account name / label (e.g., email).
    account_name: String,
    /// Number of digits (Google uses 6).
    digits: u32,
    /// Step duration in seconds (Google uses 30).
    period: u64,
}

impl TOTP {
    // ---------------------------------------------------------------------
    // 1. PRIVATE INTERNAL HELPERS (lowest level)
    // ---------------------------------------------------------------------

    /// Internal helper: generate TOTP for a given counter step.
    fn generate_for_step(&self, step: u64) -> Result<String, Box<dyn Error>> {
        // Counter as 8-byte big-endian
        let counter_bytes = step.to_be_bytes();

        // HMAC-SHA1(secret, counter)
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&self.secret)?;
        mac.update(&counter_bytes);
        let hash = mac.finalize().into_bytes();

        // Dynamic truncation (RFC 4226)
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        let binary: u32 = ((hash[offset] & 0x7f) as u32) << 24
            | ((hash[offset + 1] as u32) << 16)
            | ((hash[offset + 2] as u32) << 8)
            | (hash[offset + 3] as u32);

        // Mod 10^digits
        let modulus = 10_u32.pow(self.digits);
        let otp_int = binary % modulus;

        // Zero-padded string
        Ok(format!("{:0width$}", otp_int, width = self.digits as usize))
    }

    // ---------------------------------------------------------------------
    // 2. INTERNAL BUT EXTERNALLY USED HELPERS
    // ---------------------------------------------------------------------

    /// Generate a TOTP code for a specific Unix timestamp (seconds since epoch).
    pub fn generate_at_timestamp(&self, timestamp_secs: u64) -> Result<String, Box<dyn Error>> {
        let step = timestamp_secs / self.period;
        self.generate_for_step(step)
    }

    // ---------------------------------------------------------------------
    // 3. PUBLIC API
    // ---------------------------------------------------------------------

    /// Create TOTP from **raw bytes**.
    pub fn new(secret_bytes: &[u8], issuer: &str, account_name: &str) -> Self {
        Self {
            secret: secret_bytes.to_vec(),
            issuer: issuer.to_string(),
            account_name: account_name.to_string(),
            digits: 6,
            period: 30,
        }
    }

    /// Generate the current TOTP code based on the system clock.
    pub fn generate_current(&self) -> Result<String, Box<dyn Error>> {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.generate_at_timestamp(seconds)
    }

    /// Verify a user-provided code with a ±`window` step tolerance.
    pub fn verify(&self, code: &str, window: i64) -> Result<bool, Box<dyn Error>> {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let current_step = seconds / (self.period as i64);
        let window = window.max(0);

        for step in (current_step - window)..=(current_step + window) {
            if step < 0 {
                continue;
            }

            let candidate = self.generate_for_step(step as u64)?;
            if candidate == code {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Build an otpauth:// URI suitable for QR code encoding and importing
    /// into Google Authenticator (and most other TOTP apps).
    /// Here we encode the *raw bytes* as Base32.
    pub fn otpauth_uri(&self) -> String {
        let secret_base32 = BASE32_NOPAD.encode(&self.secret);
        let label = format!("{}:{}", self.issuer, self.account_name);
        let label_enc = encode(&label);
        let issuer_enc = encode(&self.issuer);

        format!(
            "otpauth://totp/{}?secret={}&issuer={}&digits={}&period={}",
            label_enc, secret_base32, issuer_enc, self.digits, self.period,
        )
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example raw secret bytes (in a real app, generate this randomly).
    let raw_secret: &[u8] = b"my-super-secret-totp-key";

    // 1. Encrypt the raw bytes
    let secret_encrypted = encrypt_secret(&MASTER_KEY, raw_secret);
    println!("Encrypted secret (base64 blob): {}", &secret_encrypted);

    // 2. Decrypt back into raw bytes just before use
    let secret_decrypted = decrypt_secret(&MASTER_KEY, &secret_encrypted)?;
    println!(
        "Decrypted secret (hex): {}",
        BASE32_NOPAD.encode(&secret_decrypted)
    );

    // 3. Create TOTP from raw bytes
    let totp = TOTP::new(&secret_decrypted, "MyService", "example@example.com");

    // Generate current code
    let code = totp.generate_current()?;
    println!("Current TOTP: {}", code);

    // Verify user input (pretend this came from user)
    let user_input = code.clone();
    let is_valid = totp.verify(&user_input, 1)?;
    println!("Is valid? {}", is_valid);

    // otpauth URI (raw secret is Base32-encoded here)
    let uri = totp.otpauth_uri();
    println!("otpauth URI: {}", uri);

    Ok(())
}
