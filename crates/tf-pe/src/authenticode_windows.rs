//! Narrow Windows CryptoAPI bridge for offline CMS and certificate-chain verification.
//!
//! Safety invariants:
//! - all encoded blobs borrow bounded Rust slices for the duration of each call;
//! - returned certificate and chain contexts are checked for null and freed exactly once;
//! - chain element counts are only read after successful API calls and are capped;
//! - chain retrieval is cache-only, with a zero URL timeout and no network fallback.

use std::mem::size_of;
use std::ptr::{null, null_mut};

use serde_json::{Value, json};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Security::Cryptography::{
    CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE, CERT_CHAIN_PARA,
    CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
    CERT_CONTEXT, CERT_TRUST_IS_NOT_SIGNATURE_VALID, CERT_TRUST_IS_NOT_TIME_VALID,
    CERT_TRUST_IS_OFFLINE_REVOCATION, CERT_TRUST_IS_PARTIAL_CHAIN, CERT_TRUST_IS_REVOKED,
    CERT_TRUST_IS_UNTRUSTED_ROOT, CERT_TRUST_REVOCATION_STATUS_UNKNOWN, CRYPT_VERIFY_MESSAGE_PARA,
    CertCreateCertificateContext, CertFreeCertificateChain, CertFreeCertificateContext,
    CertGetCertificateChain, CryptVerifyMessageSignature, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

use crate::authenticode::MAX_CHAIN_ELEMENTS;

const NTE_BAD_SIGNATURE: u32 = 0x8009_0006;
const CRYPT_E_BAD_MSG: u32 = 0x8009_200d;

pub(crate) fn verify(bytes: &[u8], signer_count: usize) -> Value {
    let Ok(length) = u32::try_from(bytes.len()) else {
        return unknown("cms_size_exceeds_cryptoapi_limit");
    };
    let mut signatures = Vec::new();
    let mut first_chain = None;
    for signer_index in 0..signer_count {
        let mut signer = null_mut::<CERT_CONTEXT>();
        let mut decoded_length = 0_u32;
        let parameters = CRYPT_VERIFY_MESSAGE_PARA {
            cbSize: size_of::<CRYPT_VERIFY_MESSAGE_PARA>() as u32,
            dwMsgAndCertEncodingType: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            hCryptProv: 0,
            pfnGetSignerCertificate: None,
            pvGetArg: null_mut(),
        };
        // SAFETY: parameters and output pointers are valid; `bytes` is a bounded live slice.
        let valid = unsafe {
            CryptVerifyMessageSignature(
                &parameters,
                signer_index as u32,
                bytes.as_ptr(),
                length,
                null_mut(),
                &mut decoded_length,
                &mut signer,
            )
        };
        let error = if valid == 0 {
            // SAFETY: GetLastError has no pointer or lifetime requirements.
            unsafe { GetLastError() }
        } else {
            0
        };
        let status = if valid != 0 {
            "valid"
        } else if matches!(error, NTE_BAD_SIGNATURE | CRYPT_E_BAD_MSG) {
            "invalid"
        } else {
            "unknown"
        };
        signatures.push(json!({
            "signer_index": signer_index,
            "status": status,
            "certificate_returned": !signer.is_null(),
            "cryptoapi_error": (error != 0).then(|| format!("0x{error:08x}")),
            "method": "CryptVerifyMessageSignature",
        }));
        if valid != 0 && !signer.is_null() && first_chain.is_none() {
            first_chain = Some(build_chain(signer));
        }
        if !signer.is_null() {
            // SAFETY: CryptoAPI returned this context and ownership is released once here.
            unsafe { CertFreeCertificateContext(signer) };
        }
    }
    let chain = first_chain.unwrap_or_else(|| unknown_chain("no_cryptographically_valid_signer"));
    json!({
        "cms_signatures": signatures,
        "chain_build": chain["chain_build"].clone(),
        "publisher_trust": chain["publisher_trust"].clone(),
        "revocation": chain["revocation"].clone(),
        "offline": true,
        "network_access": false,
    })
}

pub(crate) fn verify_nested(bytes: &[u8]) -> Value {
    let result = verify(bytes, 1);
    json!({
        "status": result.pointer("/cms_signatures/0/status").cloned().unwrap_or_else(|| json!("unknown")),
        "cms_signature": result.pointer("/cms_signatures/0").cloned().unwrap_or_else(|| json!({"status": "unknown"})),
        "chain_build": result["chain_build"].clone(),
        "publisher_trust": result["publisher_trust"].clone(),
        "revocation": result["revocation"].clone(),
        "offline": true,
    })
}

pub(crate) fn chain_from_certificate(bytes: &[u8]) -> Value {
    let Ok(length) = u32::try_from(bytes.len()) else {
        return unknown_chain("certificate_size_exceeds_cryptoapi_limit");
    };
    // SAFETY: `bytes` is a bounded live DER slice for the duration of the call.
    let certificate = unsafe {
        CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            bytes.as_ptr(),
            length,
        )
    };
    if certificate.is_null() {
        // SAFETY: GetLastError has no pointer or lifetime requirements.
        let error = unsafe { GetLastError() };
        return unknown_chain(&format!(
            "CertCreateCertificateContext_failed_0x{error:08x}"
        ));
    }
    let chain = build_chain(certificate);
    // SAFETY: CryptoAPI returned this context and ownership is released once here.
    unsafe { CertFreeCertificateContext(certificate) };
    chain
}

fn build_chain(signer: *const CERT_CONTEXT) -> Value {
    let parameters = CERT_CHAIN_PARA {
        cbSize: size_of::<CERT_CHAIN_PARA>() as u32,
        dwUrlRetrievalTimeout: 0,
        ..Default::default()
    };
    let mut chain = null_mut();
    // SAFETY: signer is a live context returned by CryptoAPI. Cache-only flags prohibit network
    // retrieval; the signer's message store is borrowed as the additional embedded-cert store.
    let built = unsafe {
        CertGetCertificateChain(
            null_mut(),
            signer,
            null(),
            (*signer).hCertStore,
            &parameters,
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
                | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE
                | CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY,
            null(),
            &mut chain,
        )
    };
    if built == 0 || chain.is_null() {
        // SAFETY: GetLastError has no pointer or lifetime requirements.
        let error = unsafe { GetLastError() };
        return unknown_chain(&format!("CertGetCertificateChain_failed_0x{error:08x}"));
    }
    // SAFETY: successful CertGetCertificateChain returned a live CERT_CHAIN_CONTEXT.
    let context = unsafe { &*chain };
    let errors = context.TrustStatus.dwErrorStatus;
    let chain_count = context.cChain.min(MAX_CHAIN_ELEMENTS);
    let mut element_count = 0_u32;
    if chain_count != 0 && !context.rgpChain.is_null() {
        // SAFETY: at least one simple-chain pointer is present after successful chain creation.
        let simple = unsafe { *context.rgpChain };
        if !simple.is_null() {
            // SAFETY: the simple chain belongs to the live chain context.
            element_count = unsafe { (*simple).cElement.min(MAX_CHAIN_ELEMENTS) };
        }
    }
    let revocation = if errors & CERT_TRUST_IS_REVOKED != 0 {
        json!({"status": "revoked", "source": "local_cached_chain_state"})
    } else if errors & (CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION)
        != 0
    {
        json!({"status": "unknown", "reason": "offline_cache_has_no_conclusive_revocation_status", "network_access": false})
    } else {
        json!({"status": "not_reported_revoked_by_offline_cache", "limitation": "not_equivalent_to_current_online_revocation"})
    };
    let revocation_errors = CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION;
    let non_revocation_errors = errors & !revocation_errors;
    let trust = if errors & CERT_TRUST_IS_REVOKED != 0 {
        json!({"status": "untrusted", "reason": "certificate_reported_revoked", "local_system_roots_only": true})
    } else if non_revocation_errors == 0 {
        json!({"status": "trusted_local_system_root", "offline": true, "local_system_roots_only": true})
    } else if errors & CERT_TRUST_IS_UNTRUSTED_ROOT != 0 {
        json!({"status": "untrusted", "reason": "untrusted_root", "local_system_roots_only": true})
    } else {
        json!({"status": "unknown", "reason": "offline_chain_has_errors", "error_status": format!("0x{errors:08x}"), "local_system_roots_only": true})
    };
    let result = json!({
        "chain_build": {
            "status": if errors & (CERT_TRUST_IS_PARTIAL_CHAIN | CERT_TRUST_IS_NOT_SIGNATURE_VALID) == 0 { "built" } else { "incomplete_or_invalid" },
            "simple_chain_count": chain_count,
            "element_count": element_count,
            "error_status": format!("0x{errors:08x}"),
            "signature_valid": errors & CERT_TRUST_IS_NOT_SIGNATURE_VALID == 0,
            "time_valid": errors & CERT_TRUST_IS_NOT_TIME_VALID == 0,
            "cache_only": true,
        },
        "publisher_trust": trust,
        "revocation": revocation,
    });
    // SAFETY: this context was returned once and is no longer referenced after this call.
    unsafe { CertFreeCertificateChain(chain) };
    result
}

fn unknown(reason: &str) -> Value {
    json!({
        "cms_signatures": [{"status": "unknown", "reason": reason}],
        "chain_build": {"status": "unknown", "reason": reason},
        "publisher_trust": {"status": "unknown", "reason": reason},
        "revocation": {"status": "unknown", "reason": "offline_no_network_revocation"},
        "offline": true,
        "network_access": false,
    })
}

fn unknown_chain(reason: &str) -> Value {
    json!({
        "chain_build": {"status": "unknown", "reason": reason},
        "publisher_trust": {"status": "unknown", "reason": reason},
        "revocation": {"status": "unknown", "reason": "offline_no_network_revocation"},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_or_tampered_cms_is_never_reported_valid() {
        let result = verify(b"inert malformed CMS", 1);
        assert_ne!(result["cms_signatures"][0]["status"], "valid");
        assert_ne!(
            result["publisher_trust"]["status"],
            "trusted_local_system_root"
        );
    }
}
