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

// Encrypt
pub fn encrypt_secret(key_bytes: &[u8; 32], plaintext: &str) -> String {
    let key = GenericArray::clone_from_slice(key_bytes);
    let encryptor = Aes256EcbEnc::new(&key);
    let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());
    general_purpose::STANDARD.encode(&ciphertext)
}

// Decrypt
pub fn decrypt_secret(key_bytes: &[u8; 32], blob_b64: &str) -> Result<String, Box<dyn Error>> {
    let ciphertext = general_purpose::STANDARD.decode(blob_b64)?;
    let key = GenericArray::clone_from_slice(key_bytes);
    let decryptor = Aes256EcbDec::new(&key);
    let decrypted = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .map_err(|e| -> Box<dyn Error> {
            Box::<dyn Error>::from(format!("Unpadding failed: {:?}", e))
        })?;
    Ok(String::from_utf8(decrypted)?)
}

/// Google Auth–compatible TOTP helper.
/// - 6 digits
/// - HMAC-SHA1
/// - 30-second period
#[derive(Debug, Clone)]
pub struct TOTP {
    /// Secret as raw bytes (decoded from Base32).
    secret: Vec<u8>,
    /// Original Base32 secret (useful for otpauth:// URIs).
    secret_base32: String,
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
    /// Create a new GoogleTotp from a Base32 secret, issuer and account name.
    /// `secret_base32` should be unpadded Base32 like Google Auth uses.
    pub fn new(
        secret_base32: &str,
        issuer: &str,
        account_name: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let secret = BASE32_NOPAD.decode(secret_base32.as_bytes())?;

        Ok(Self {
            secret,
            secret_base32: secret_base32.to_string(),
            issuer: issuer.to_string(),
            account_name: account_name.to_string(),
            digits: 6,
            period: 30,
        })
    }

    /// Generate the current TOTP code based on the system clock.
    pub fn generate_current(&self) -> Result<String, Box<dyn Error>> {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.generate_at_timestamp(seconds)
    }

    /// Verify a user-provided code with a ±`window` step tolerance.
    ///
    /// Example: `window = 1` checks [current-1, current, current+1] time steps.
    pub fn verify(&self, code: &str, window: i64) -> Result<bool, Box<dyn Error>> {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let current_step = seconds / (self.period as i64);
        let window = window.max(0); // avoid negative windows

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
    pub fn otpauth_uri(&self) -> String {
        let label = format!("{}:{}", self.issuer, self.account_name);
        let label_enc = encode(&label);
        let issuer_enc = encode(&self.issuer);

        format!(
            "otpauth://totp/{}?secret={}&issuer={}&digits={}&period={}",
            label_enc, self.secret_base32, issuer_enc, self.digits, self.period,
        )
    }

    /// Generate a TOTP code for a specific Unix timestamp (seconds since epoch).
    /// This is mostly useful for tests or custom verification.
    pub fn generate_at_timestamp(&self, timestamp_secs: u64) -> Result<String, Box<dyn Error>> {
        let step = timestamp_secs / self.period;
        self.generate_for_step(step)
    }

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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example Base32 secret (DO NOT hardcode in real apps)
    let secret = "JBSWY3DPEHPK3PXP";

    let secret_encrypted = encrypt_secret(&MASTER_KEY, secret);
    println!(
        "Encrypted Base32 secret (base64 blob): {}",
        &secret_encrypted
    );

    // Later, decrypt just before use
    let secret_decrypted = decrypt_secret(&MASTER_KEY, &secret_encrypted)?;
    println!("Decrypted Base32 secret: {}", &secret_decrypted);

    let totp = TOTP::new(&secret_decrypted, "MyService", "josh@example.com")?;

    // 1. Generate current code
    let code = totp.generate_current()?;
    println!("Current TOTP: {}", code);

    // 2. Verify user input (e.g., from a form), with ±1 step window
    let user_input = code.clone(); // pretend this came from the user
    let is_valid = totp.verify(&user_input, 1)?;
    println!("Is valid? {}", is_valid);

    // 3. Get otpauth URI to embed into a QR code
    let uri = totp.otpauth_uri();
    println!("otpauth URI: {}", uri);

    Ok(())
}
