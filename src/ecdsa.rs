//! Elliptic Curve Digital Signature Algorithm (ECDSA)
//!
//! This module contains support for computing and verifying ECDSA signatures.
//! To use it, you will need to enable one of the two following Cargo features:
//!
//! - `ecdsa-core`: provides only the [`Signature`] type (which represents an
//!   ECDSA/P-384 signature). Does not require the `arithmetic` feature. This is
//!   useful for 3rd-party crates which wish to use the `Signature` type for
//!   interoperability purposes (particularly in conjunction with the
//!   [`signature::Signer`] trait. Example use cases for this include other
//!   software implementations of ECDSA/P-384 and wrappers for cloud KMS
//!   services or hardware devices (HSM or crypto hardware wallet).
//! - `ecdsa`: provides `ecdsa-core` features plus the [`SigningKey`] and
//!   [`VerifyingKey`] types which natively implement ECDSA/P-384 signing and
//!   verification.
//!
//! ## Signing/Verification Example
//!
//! This example requires the `ecdsa` Cargo feature is enabled:
//!
//! ```
//! # #[cfg(feature = "ecdsa")]
//! # {
//! use p384_rs::ecdsa::{signature::Signer, Signature, SigningKey};
//! use rand_core::OsRng; // requires 'getrandom' feature
//!
//! // Signing
//! let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
//! let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
//! let signature = signing_key.sign(message);
//!
//! // Verification
//! use p384_rs::ecdsa::{signature::Verifier, VerifyingKey};
//!
//! let verifying_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`
//! assert!(verifying_key.verify(message, &signature).is_ok());
//! # }
//! ```

pub use ecdsa_core::signature::{self, Error};
#[cfg(feature = "ecdsa")]
use {
    crate::{AffinePoint, Scalar},
    ecdsa_core::hazmat::{SignPrimitive, VerifyPrimitive},
};

use super::NistP384;

/// ECDSA/P-384 signature (fixed-size)
pub type Signature = ecdsa_core::Signature<NistP384>;

/// ECDSA/P-384 signature (ASN.1 DER encoded)
pub type DerSignature = ecdsa_core::der::Signature<NistP384>;

/// ECDSA/P-384 signing key
#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub type SigningKey = ecdsa_core::SigningKey<NistP384>;

/// ECDSA/P-384 verification key (i.e. public key)
#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub type VerifyingKey = ecdsa_core::VerifyingKey<NistP384>;

#[cfg(feature = "sha384")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha384")))]
impl ecdsa_core::hazmat::DigestPrimitive for NistP384 {
    type Digest = sha2::Sha384;
}

#[cfg(feature = "ecdsa")]
impl SignPrimitive<NistP384> for Scalar {}

#[cfg(feature = "ecdsa")]
impl VerifyPrimitive<NistP384> for AffinePoint {}

#[cfg(feature = "ecdsa")]
#[test]
fn signing_secret_key_equivalent() {
    use crate::SecretKey;

    let raw_sk: [u8; 48] = [
        32, 52, 118, 9, 96, 116, 119, 172, 168, 251, 251, 197, 230, 33, 132, 85, 243, 25, 150, 105,
        121, 46, 248, 180, 102, 250, 168, 123, 220, 103, 121, 129, 68, 200, 72, 221, 3, 102, 30,
        237, 90, 198, 36, 97, 52, 12, 234, 150,
    ];

    let sigk = SigningKey::from_bytes(raw_sk.as_slice()).unwrap();
    let seck = SecretKey::from_be_bytes(raw_sk.as_slice()).unwrap();

    assert_eq!(sigk.to_bytes().as_slice(), &raw_sk);
    assert_eq!(sigk.to_bytes(), seck.to_be_bytes());
}

#[cfg(feature = "ecdsa")]
#[test]
fn verifying_key_equivalent() {
    let raw_sk: [u8; 48] = [
        32, 52, 118, 9, 96, 116, 119, 172, 168, 251, 251, 197, 230, 33, 132, 85, 243, 25, 150, 105,
        121, 46, 248, 180, 102, 250, 168, 123, 220, 103, 121, 129, 68, 200, 72, 221, 3, 102, 30,
        237, 90, 198, 36, 97, 52, 12, 234, 150,
    ];
    let raw_pk: [u8; 49] = [
        2, 251, 203, 124, 105, 238, 28, 96, 87, 155, 231, 163, 52, 19, 72, 120, 217, 197, 197, 191,
        53, 213, 82, 218, 182, 60, 1, 64, 57, 126, 209, 76, 239, 99, 125, 119, 32, 146, 92, 68,
        105, 158, 163, 14, 114, 135, 76, 114, 251,
    ];
    let signing_key = SigningKey::from_bytes(raw_sk.as_slice()).unwrap();

    let type_pk = VerifyingKey::from(&signing_key).to_encoded_point(true);
    let sec1_pk = VerifyingKey::from_sec1_bytes(raw_pk.as_slice())
        .unwrap()
        .to_encoded_point(true);

    assert_eq!(type_pk.as_bytes(), &raw_pk);
    assert_eq!(sec1_pk, type_pk);
}

#[cfg(feature = "ecdsa")]
#[test]
fn point_compression_wycheproof() {
    let pk_uncompressed: [u8; 97] = [
        4, 45, 165, 125, 218, 16, 137, 39, 106, 84, 63, 159, 253, 172, 11, 255, 13, 151, 108, 173,
        113, 235, 114, 128, 231, 217, 191, 217, 254, 228, 189, 178, 242, 15, 71, 255, 136, 130,
        116, 56, 151, 114, 217, 140, 197, 117, 33, 56, 170, 75, 109, 5, 77, 105, 220, 243, 226, 94,
        196, 157, 248, 112, 113, 94, 52, 136, 59, 24, 54, 25, 125, 118, 248, 173, 150, 46, 120,
        246, 87, 27, 188, 116, 7, 176, 214, 9, 31, 158, 77, 136, 240, 20, 39, 68, 6, 23, 79,
    ];

    let sec1_pk = VerifyingKey::from_sec1_bytes(pk_uncompressed.as_slice())
        .unwrap()
        .to_encoded_point(true);
    let roundtrip = VerifyingKey::from_sec1_bytes(&sec1_pk.as_bytes()).unwrap();

    assert_eq!(
        roundtrip.to_encoded_point(false).as_bytes(),
        pk_uncompressed
    );
}