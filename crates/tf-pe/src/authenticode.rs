//! Bounded Authenticode digest, CMS, timestamp, and embedded-chain inspection.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::io::{Read, Seek, SeekFrom};

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::{Decode, Encode, asn1::Any};
use rsa::{Pkcs1v15Sign, RsaPublicKey, pkcs1::DecodeRsaPublicKey};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tf_model::ObservationClass;
use x509_cert::Certificate;

use crate::WorkerFailure;
use crate::analysis::{EvidenceDraft, Image};

const WIN_CERT_REVISION_2_0: u16 = 0x0200;
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
const MAX_CERTIFICATE_ENTRIES: usize = 64;
const MAX_PKCS7_BYTES: usize = 16 * 1024 * 1024;
const MAX_EMBEDDED_CERTIFICATES: usize = 128;
const MAX_SIGNERS: usize = 64;
const MAX_TIMESTAMPS: usize = 64;
pub(crate) const MAX_CHAIN_ELEMENTS: u32 = 128;
const OID_COUNTERSIGNATURE: &str = "1.2.840.113549.1.9.6";
const OID_RFC3161: &str = "1.3.6.1.4.1.311.3.3.1";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const OID_SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
const OID_SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";

pub(crate) fn provenance_parameters() -> Value {
    json!({
        "max_certificate_entries": MAX_CERTIFICATE_ENTRIES,
        "max_pkcs7_bytes": MAX_PKCS7_BYTES,
        "max_embedded_certificates": MAX_EMBEDDED_CERTIFICATES,
        "max_signers": MAX_SIGNERS,
        "max_timestamps": MAX_TIMESTAMPS,
        "max_platform_chain_elements": MAX_CHAIN_ELEMENTS,
        "network_retrieval": false,
        "revocation_check": "cache_only",
    })
}

pub(crate) fn parse<R: Read + Seek>(
    file: &mut R,
    file_len: u64,
    image: &Image,
    records: &mut Vec<EvidenceDraft>,
) -> Result<(), WorkerFailure> {
    let table_offset = image.directories[4].rva;
    let table_size = image.directories[4].size;
    if table_offset == 0 || table_size == 0 {
        records.push(EvidenceDraft::observed(
            "pe.authenticode",
            BTreeMap::new(),
            json!({
                "present": false,
                "table_offset": table_offset,
                "table_size": table_size,
                "structural_status": "absent",
            }),
        ));
        records.push(verification_unknown("signature_absent"));
        records.push(trust_evidence(false, &platform_unknown("signature_absent")));
        return Ok(());
    }

    let start = u64::from(table_offset);
    let size = u64::from(table_size);
    if start > file_len || size > file_len - start {
        records.push(certificate_status(
            start,
            0,
            table_offset,
            table_size,
            0,
            0,
            0,
            "table_out_of_bounds",
            Value::Null,
        ));
        records.push(verification_unknown("certificate_table_out_of_bounds"));
        records.push(trust_evidence(
            true,
            &platform_unknown("certificate_table_out_of_bounds"),
        ));
        return Ok(());
    }

    let end = start + size;
    let mut cursor = start;
    let mut entry_index = 0_usize;
    let mut trust = platform_unknown("no_parseable_pkcs7_signer");
    let mut structural_records = Vec::new();
    let mut verification_records = Vec::new();
    while cursor < end && entry_index < MAX_CERTIFICATE_ENTRIES {
        if end - cursor < 8 {
            structural_records.push(certificate_status(
                cursor,
                entry_index,
                table_offset,
                table_size,
                0,
                0,
                0,
                "truncated_win_certificate_header",
                Value::Null,
            ));
            verification_records.push(verification_unknown_at(
                entry_index,
                "truncated_win_certificate_header",
            ));
            break;
        }
        file.seek(SeekFrom::Start(cursor))?;
        let mut header = [0_u8; 8];
        file.read_exact(&mut header)?;
        let length = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let revision = u16::from_le_bytes([header[4], header[5]]);
        let certificate_type = u16::from_le_bytes([header[6], header[7]]);
        if length < 8 || u64::from(length) > end - cursor {
            structural_records.push(certificate_status(
                cursor,
                entry_index,
                table_offset,
                table_size,
                length,
                revision,
                certificate_type,
                "invalid_win_certificate_length",
                Value::Null,
            ));
            verification_records.push(verification_unknown_at(
                entry_index,
                "invalid_win_certificate_length",
            ));
            break;
        }
        let payload_len = length as usize - 8;
        let (details, verification) = if revision != WIN_CERT_REVISION_2_0 {
            (
                json!({"status": "unsupported_revision"}),
                verification_value(entry_index, "unsupported_revision"),
            )
        } else if certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            (
                json!({"status": "unsupported_certificate_type"}),
                verification_value(entry_index, "unsupported_certificate_type"),
            )
        } else if payload_len > MAX_PKCS7_BYTES {
            (
                json!({"status": "pkcs7_size_limit", "limit_bytes": MAX_PKCS7_BYTES}),
                verification_value(entry_index, "pkcs7_size_limit"),
            )
        } else {
            let mut payload = vec![0_u8; payload_len];
            file.read_exact(&mut payload)?;
            let inspection = inspect_pkcs7(file, file_len, image, &payload, entry_index)?;
            trust = inspection.platform.clone();
            (inspection.details, inspection.verification)
        };
        let structural_status = details
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("parsed")
            .to_owned();
        structural_records.push(certificate_status(
            cursor,
            entry_index,
            table_offset,
            table_size,
            length,
            revision,
            certificate_type,
            &structural_status,
            details,
        ));
        verification_records.push(EvidenceDraft::observed(
            "pe.authenticode.verification",
            BTreeMap::from([("entry_index".to_owned(), json!(entry_index))]),
            verification,
        ));
        entry_index += 1;
        let aligned = u64::from(length)
            .checked_add(7)
            .map(|value| value & !7)
            .ok_or_else(|| WorkerFailure::invalid_pe("WIN_CERTIFICATE alignment overflowed"))?;
        cursor = cursor
            .checked_add(aligned)
            .ok_or_else(|| WorkerFailure::invalid_pe("WIN_CERTIFICATE offset overflowed"))?;
    }
    if entry_index == MAX_CERTIFICATE_ENTRIES && cursor < end {
        structural_records.push(certificate_status(
            cursor,
            entry_index,
            table_offset,
            table_size,
            0,
            0,
            0,
            "certificate_entry_limit",
            json!({"limit": MAX_CERTIFICATE_ENTRIES}),
        ));
    }
    records.extend(structural_records);
    records.extend(verification_records);
    records.push(trust_evidence(true, &trust));
    Ok(())
}

struct Inspection {
    details: Value,
    verification: Value,
    platform: Value,
}

fn inspect_pkcs7<R: Read + Seek>(
    file: &mut R,
    file_len: u64,
    image: &Image,
    bytes: &[u8],
    entry_index: usize,
) -> Result<Inspection, WorkerFailure> {
    let content = match ContentInfo::from_der(bytes) {
        Ok(content) => content,
        Err(error) => {
            return Ok(malformed(
                entry_index,
                "malformed_content_info",
                error.to_string(),
            ));
        }
    };
    if content.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        return Ok(malformed(
            entry_index,
            "not_signed_data",
            content.content_type.to_string(),
        ));
    }
    let signed_der = match content.content.to_der() {
        Ok(encoded) => encoded,
        Err(error) => {
            return Ok(malformed(
                entry_index,
                "malformed_signed_data",
                error.to_string(),
            ));
        }
    };
    let signed = match SignedData::from_der(&signed_der) {
        Ok(signed) => signed,
        Err(error) => {
            return Ok(malformed(
                entry_index,
                "malformed_signed_data",
                error.to_string(),
            ));
        }
    };
    let certificates: Vec<&Certificate> = signed
        .certificates
        .as_ref()
        .map(|set| {
            set.0
                .iter()
                .filter_map(|choice| match choice {
                    CertificateChoices::Certificate(certificate) => Some(certificate),
                    CertificateChoices::Other(_) => None,
                })
                .take(MAX_EMBEDDED_CERTIFICATES)
                .collect()
        })
        .unwrap_or_default();
    let digest_algorithms: Vec<_> = signed
        .digest_algorithms
        .iter()
        .map(|algorithm| algorithm.oid.to_string())
        .collect();
    let certificate_details: Vec<_> = certificates.iter().map(certificate_json).collect();
    let encapsulated_content = signed.encap_content_info.econtent.as_ref();
    let mut signer_details = Vec::new();
    let mut cms_signatures = Vec::new();
    let mut timestamp_details = Vec::new();
    let mut embedded_chains = Vec::new();
    for (index, signer) in signed.signer_infos.0.iter().take(MAX_SIGNERS).enumerate() {
        let matched_index = certificates
            .iter()
            .position(|certificate| signer_matches(signer, certificate));
        let matched = matched_index.map(|position| certificates[position]);
        let cms_signature = verify_cms_signer(signer, matched, encapsulated_content, index);
        signer_details.push(json!({
            "index": index,
            "identifier": signer_identifier_json(&signer.sid),
            "digest_algorithm_oid": signer.digest_alg.oid.to_string(),
            "signature_algorithm_oid": signer.signature_algorithm.oid.to_string(),
            "signature_length": signer.signature.as_bytes().len(),
            "certificate_matched": matched.is_some(),
            "certificate_index": matched_index,
            "subject": matched.map(|certificate| bounded_display(&certificate.tbs_certificate.subject)),
            "issuer": matched.map(|certificate| bounded_display(&certificate.tbs_certificate.issuer)),
            "serial": matched.map(|certificate| bounded_display(&certificate.tbs_certificate.serial_number)),
            "cryptographic_status": cms_signature.get("status").cloned().unwrap_or_else(|| json!("unknown")),
        }));
        cms_signatures.push(cms_signature);
        embedded_chains.push(build_embedded_chain(index, matched_index, &certificates));
        if let Some(attributes) = &signer.unsigned_attrs {
            for attribute in attributes.iter() {
                let oid = attribute.oid.to_string();
                if oid != OID_COUNTERSIGNATURE && oid != OID_RFC3161 {
                    continue;
                }
                for value in attribute
                    .values
                    .iter()
                    .take(MAX_TIMESTAMPS.saturating_sub(timestamp_details.len()))
                {
                    let der = value.to_der().ok();
                    let structure = der
                        .as_deref()
                        .map(|bytes| timestamp_structure(&oid, bytes, signer.signature.as_bytes()));
                    let crypto = if oid == OID_RFC3161 {
                        der.as_deref()
                            .map(platform_verify_nested)
                            .unwrap_or_else(|| platform_unknown("malformed_rfc3161_value"))
                    } else {
                        platform_unknown("classic_countersignature_crypto_not_safely_supported")
                    };
                    let cms_valid = crypto.get("status").and_then(Value::as_str) == Some("valid");
                    let imprint_matches = structure
                        .as_ref()
                        .and_then(|value| value.get("message_imprint_matches"))
                        .and_then(Value::as_bool);
                    let validity = if oid == OID_RFC3161
                        && cms_valid
                        && imprint_matches == Some(true)
                    {
                        json!({"status": "valid", "scope": "token_cms_signature_and_parent_signature_imprint"})
                    } else if oid == OID_RFC3161
                        && (crypto.get("status").and_then(Value::as_str) == Some("invalid")
                            || imprint_matches == Some(false))
                    {
                        json!({"status": "invalid", "reason": if imprint_matches == Some(false) { "parent_signature_imprint_mismatch" } else { "timestamp_cms_signature_invalid" }})
                    } else {
                        json!({"status": "unknown", "reason": "timestamp_crypto_or_imprint_not_fully_established"})
                    };
                    timestamp_details.push(json!({
                        "parent_signer_index": index,
                        "kind": if oid == OID_RFC3161 { "rfc3161" } else { "cms_countersignature" },
                        "oid": oid,
                        "structural_status": if der.is_some() { "parsed_attribute_value" } else { "malformed_attribute_value" },
                        "structure": structure,
                        "cryptographic_verification": crypto,
                        "timestamp_validity": validity,
                    }));
                }
            }
        }
    }
    let signed_digest = signed
        .encap_content_info
        .econtent
        .as_ref()
        .and_then(|content| {
            content
                .to_der()
                .ok()
                .and_then(|der| parse_spc_indirect_digest(&der))
        });
    let digest_verification = match signed_digest {
        Some((algorithm, expected)) => {
            match authenticode_digest(file, file_len, image, algorithm) {
                Ok(calculated) => json!({
                    "status": "observed",
                    "algorithm": algorithm.name(),
                    "algorithm_oid": algorithm.oid(),
                    "signed_digest": hex(&expected),
                    "calculated_digest": hex(&calculated),
                    "matches": calculated == expected,
                    "exclusions": ["optional_header_checksum", "security_data_directory_entry", "certificate_table"],
                }),
                Err(reason) => json!({"status": "unknown", "reason": reason}),
            }
        }
        None => json!({"status": "unknown", "reason": "spc_indirect_data_digest_not_parseable"}),
    };
    let mut platform = platform_verify(bytes, signed.signer_infos.0.len().min(MAX_SIGNERS));
    let chain_certificate = signed
        .signer_infos
        .0
        .iter()
        .take(MAX_SIGNERS)
        .enumerate()
        .find(|(index, _)| {
            cms_signatures[*index].get("status").and_then(Value::as_str) == Some("valid")
        })
        .and_then(|(_, signer)| {
            certificates
                .iter()
                .find(|certificate| signer_matches(signer, certificate))
        })
        .and_then(|certificate| certificate.to_der().ok());
    if let Some(certificate) = chain_certificate {
        let chain = platform_chain_certificate(&certificate);
        if let Some(fields) = platform.as_object_mut() {
            for key in ["chain_build", "publisher_trust", "revocation"] {
                if let Some(value) = chain.get(key) {
                    fields.insert(key.to_owned(), value.clone());
                }
            }
        }
    }
    let details = json!({
        "status": "parsed",
        "content_type_oid": content.content_type.to_string(),
        "encapsulated_content_type_oid": signed.encap_content_info.econtent_type.to_string(),
        "digest_algorithm_oids": digest_algorithms,
        "certificate_count": signed.certificates.as_ref().map_or(0, |set| set.0.len()),
        "certificates_emitted": certificates.len(),
        "certificates": certificate_details,
        "signer_count": signed.signer_infos.0.len(),
        "signers_emitted": signer_details.len(),
        "signers": signer_details,
    });
    let verification = json!({
        "entry_index": entry_index,
        "image_digest": digest_verification,
        "cms_signatures": cms_signatures,
        "timestamps": timestamp_details,
        "embedded_chains": embedded_chains,
        "chain_build": platform.get("chain_build").cloned().unwrap_or_else(|| json!({"status": "unknown"})),
        "publisher_trust": platform.get("publisher_trust").cloned().unwrap_or_else(|| json!({"status": "unknown"})),
        "revocation": platform.get("revocation").cloned().unwrap_or_else(|| json!({"status": "unknown"})),
        "limitations": [
            "offline_only_no_network_or_online_revocation",
            "cryptographic_validity_is_not_a_safety_verdict",
            "local_root_chain_is_not_a_complete_winverifytrust_or_eku_policy_verdict",
            "unsupported_algorithms_remain_unknown",
        ],
        "safe_file_assessment": {"status": "unknown", "reason": "not_assessed"},
        "safe_file_claim": "not_made",
    });
    Ok(Inspection {
        details,
        verification,
        platform,
    })
}

fn verify_cms_signer(
    signer: &cms::signed_data::SignerInfo,
    certificate: Option<&Certificate>,
    content: Option<&Any>,
    signer_index: usize,
) -> Value {
    let Some(certificate) = certificate else {
        return cms_unknown(signer_index, "signer_certificate_not_found");
    };
    let Some(content) = content else {
        return cms_unknown(signer_index, "encapsulated_content_not_available");
    };
    let Some(algorithm) = hash_algorithm_from_identifier(&signer.digest_alg.oid.to_string()) else {
        return cms_unknown(signer_index, "unsupported_digest_algorithm");
    };
    if !rsa_signature_algorithm(&signer.signature_algorithm.oid.to_string()) {
        return cms_unknown(signer_index, "unsupported_signature_algorithm");
    }

    let (signed_bytes, content_digest_matches, content_digest_encoding) =
        if let Some(attributes) = &signer.signed_attrs {
            let expected = attributes
                .iter()
                .find(|attribute| attribute.oid.to_string() == OID_MESSAGE_DIGEST)
                .and_then(|attribute| attribute.values.iter().next())
                .and_then(|value| {
                    value
                        .to_der()
                        .ok()
                        .and_then(|der| tlv_content(&der, 0, 0x04).map(ToOwned::to_owned))
                });
            let Some(expected) = expected else {
                return cms_unknown(signer_index, "signed_attributes_missing_message_digest");
            };
            let Some(encoded) = attributes.to_der().ok() else {
                return cms_unknown(signer_index, "signed_attributes_encoding_failed");
            };
            let value_matches = digest_bytes(algorithm, content.value()) == expected;
            let der_matches = !value_matches
                && content
                    .to_der()
                    .ok()
                    .is_some_and(|encoded| digest_bytes(algorithm, &encoded) == expected);
            (
                encoded,
                Some(value_matches || der_matches),
                Some(if value_matches {
                    "content_value_octets"
                } else if der_matches {
                    "encoded_content_der"
                } else {
                    "no_supported_encoding_matched"
                }),
            )
        } else {
            (content.value().to_vec(), None, None)
        };

    let public_key = certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let Ok(public_key) = RsaPublicKey::from_pkcs1_der(public_key) else {
        return cms_unknown(signer_index, "rsa_public_key_not_parseable");
    };
    let signature_valid = verify_rsa_pkcs1v15(
        &public_key,
        algorithm,
        &signed_bytes,
        signer.signature.as_bytes(),
    );
    let status = if signature_valid && content_digest_matches != Some(false) {
        "valid"
    } else {
        "invalid"
    };
    json!({
        "signer_index": signer_index,
        "status": status,
        "certificate_returned": true,
        "signature_valid": signature_valid,
        "content_digest_matches": content_digest_matches,
        "content_digest_encoding": content_digest_encoding,
        "digest_algorithm": algorithm.name(),
        "method": "bounded_rust_cms_rsa_pkcs1v15",
    })
}

fn verify_rsa_pkcs1v15(
    public_key: &RsaPublicKey,
    algorithm: HashAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> bool {
    let digest = digest_bytes(algorithm, message);
    let padding = match algorithm {
        HashAlgorithm::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
        HashAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        HashAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        HashAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    };
    public_key.verify(padding, &digest, signature).is_ok()
}

fn hash_algorithm_from_identifier(oid: &str) -> Option<HashAlgorithm> {
    match oid {
        "1.3.14.3.2.26" => Some(HashAlgorithm::Sha1),
        "2.16.840.1.101.3.4.2.1" => Some(HashAlgorithm::Sha256),
        "2.16.840.1.101.3.4.2.2" => Some(HashAlgorithm::Sha384),
        "2.16.840.1.101.3.4.2.3" => Some(HashAlgorithm::Sha512),
        _ => None,
    }
}

fn rsa_signature_algorithm(oid: &str) -> bool {
    matches!(
        oid,
        OID_RSA_ENCRYPTION
            | OID_SHA1_WITH_RSA
            | OID_SHA256_WITH_RSA
            | OID_SHA384_WITH_RSA
            | OID_SHA512_WITH_RSA
    )
}

fn cms_unknown(signer_index: usize, reason: &str) -> Value {
    json!({
        "signer_index": signer_index,
        "status": "unknown",
        "reason": reason,
        "method": "bounded_rust_cms_rsa_pkcs1v15",
    })
}

fn malformed(entry_index: usize, status: &str, error: String) -> Inspection {
    Inspection {
        details: json!({"status": status, "error": error}),
        verification: verification_value(entry_index, status),
        platform: platform_unknown(status),
    }
}

#[derive(Clone, Copy)]
enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
    fn oid(self) -> &'static str {
        match self {
            Self::Sha1 => "1.3.14.3.2.26",
            Self::Sha256 => "2.16.840.1.101.3.4.2.1",
            Self::Sha384 => "2.16.840.1.101.3.4.2.2",
            Self::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }
}

enum ImageHasher {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl ImageHasher {
    fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Sha1 => Self::Sha1(Sha1::new()),
            HashAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            HashAlgorithm::Sha384 => Self::Sha384(Sha384::new()),
            HashAlgorithm::Sha512 => Self::Sha512(Sha512::new()),
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(value) => value.update(bytes),
            Self::Sha256(value) => value.update(bytes),
            Self::Sha384(value) => value.update(bytes),
            Self::Sha512(value) => value.update(bytes),
        }
    }
    fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha1(value) => value.finalize().to_vec(),
            Self::Sha256(value) => value.finalize().to_vec(),
            Self::Sha384(value) => value.finalize().to_vec(),
            Self::Sha512(value) => value.finalize().to_vec(),
        }
    }
}

fn authenticode_digest<R: Read + Seek>(
    file: &mut R,
    file_len: u64,
    image: &Image,
    algorithm: HashAlgorithm,
) -> Result<Vec<u8>, String> {
    if image.checksum_offset + 4 > u64::from(image.size_of_headers)
        || image.security_directory_offset + 8 > u64::from(image.size_of_headers)
        || image.checksum_offset + 4 > image.security_directory_offset
        || u64::from(image.size_of_headers) > file_len
    {
        return Err("invalid_authenticode_header_ranges".to_owned());
    }
    let mut hasher = ImageHasher::new(algorithm);
    hash_file_range(file, &mut hasher, 0, image.checksum_offset)
        .map_err(|_| "image_digest_io_failure".to_owned())?;
    hash_file_range(
        file,
        &mut hasher,
        image.checksum_offset + 4,
        image.security_directory_offset - image.checksum_offset - 4,
    )
    .map_err(|_| "image_digest_io_failure".to_owned())?;
    hash_file_range(
        file,
        &mut hasher,
        image.security_directory_offset + 8,
        u64::from(image.size_of_headers) - image.security_directory_offset - 8,
    )
    .map_err(|_| "image_digest_io_failure".to_owned())?;
    let mut sections: Vec<_> = image
        .sections
        .iter()
        .map(|section| section.raw_range())
        .filter(|(_, size)| *size != 0)
        .collect();
    sections.sort_by_key(|(offset, _)| *offset);
    let mut summed = u64::from(image.size_of_headers);
    for (offset, size) in sections {
        let offset = u64::from(offset);
        let size = u64::from(size);
        if offset > file_len || size > file_len - offset {
            return Err("section_out_of_bounds_during_image_digest".to_owned());
        }
        hash_file_range(file, &mut hasher, offset, size)
            .map_err(|_| "image_digest_io_failure".to_owned())?;
        summed = summed
            .checked_add(size)
            .ok_or_else(|| "image_digest_size_overflow".to_owned())?;
    }
    if summed > file_len {
        return Err("invalid_authenticode_extra_data_range".to_owned());
    }
    let certificate_start = u64::from(image.directories[4].rva);
    let certificate_size = u64::from(image.directories[4].size);
    if certificate_start == 0 || certificate_size == 0 {
        hash_file_range(file, &mut hasher, summed, file_len - summed)
            .map_err(|_| "image_digest_io_failure".to_owned())?;
    } else {
        let certificate_end = certificate_start
            .checked_add(certificate_size)
            .ok_or_else(|| "certificate_table_range_overflow".to_owned())?;
        if certificate_start > file_len || certificate_end > file_len {
            return Err("certificate_table_out_of_bounds_during_image_digest".to_owned());
        }
        if summed < certificate_start {
            hash_file_range(file, &mut hasher, summed, certificate_start - summed)
                .map_err(|_| "image_digest_io_failure".to_owned())?;
        }
        let after = certificate_end.max(summed);
        if after < file_len {
            hash_file_range(file, &mut hasher, after, file_len - after)
                .map_err(|_| "image_digest_io_failure".to_owned())?;
        }
    }
    Ok(hasher.finish())
}

fn hash_file_range<R: Read + Seek>(
    file: &mut R,
    digest: &mut ImageHasher,
    offset: u64,
    size: u64,
) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    let mut remaining = size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        file.read_exact(&mut buffer[..count])?;
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(())
}

fn parse_spc_indirect_digest(bytes: &[u8]) -> Option<(HashAlgorithm, Vec<u8>)> {
    let outer = tlv_content(bytes, 0, 0x30)?;
    let (_, first_end) = tlv_at(outer, 0)?;
    let digest_info = tlv_content(outer, first_end, 0x30)?;
    let algorithm = tlv_content(digest_info, 0, 0x30)?;
    let oid = tlv_content(algorithm, 0, 0x06)?;
    let (_, algorithm_end) = tlv_at(digest_info, 0)?;
    let digest = tlv_content(digest_info, algorithm_end, 0x04)?.to_vec();
    let algorithm = match oid {
        [0x2b, 0x0e, 0x03, 0x02, 0x1a] => HashAlgorithm::Sha1,
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => HashAlgorithm::Sha256,
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => HashAlgorithm::Sha384,
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => HashAlgorithm::Sha512,
        _ => return None,
    };
    (digest.len() == digest_length(algorithm)).then_some((algorithm, digest))
}

fn timestamp_structure(oid: &str, bytes: &[u8], parent_signature: &[u8]) -> Value {
    if oid == OID_COUNTERSIGNATURE {
        return match cms::signed_data::SignerInfo::from_der(bytes) {
            Ok(signer) => json!({
                "status": "parsed",
                "identifier": signer_identifier_json(&signer.sid),
                "digest_algorithm_oid": signer.digest_alg.oid.to_string(),
                "signature_algorithm_oid": signer.signature_algorithm.oid.to_string(),
                "signature_length": signer.signature.as_bytes().len(),
            }),
            Err(error) => json!({"status": "malformed", "error": error.to_string()}),
        };
    }
    let content = match ContentInfo::from_der(bytes) {
        Ok(content) => content,
        Err(error) => {
            return json!({"status": "malformed_content_info", "error": error.to_string()});
        }
    };
    let signed_der = match content.content.to_der() {
        Ok(value) => value,
        Err(error) => return json!({"status": "malformed_signed_data", "error": error.to_string()}),
    };
    let signed = match SignedData::from_der(&signed_der) {
        Ok(value) => value,
        Err(error) => return json!({"status": "malformed_signed_data", "error": error.to_string()}),
    };
    let imprint = signed
        .encap_content_info
        .econtent
        .as_ref()
        .and_then(|content| {
            content.to_der().ok().and_then(|encoded| {
                let tst = tlv_content(&encoded, 0, 0x04).unwrap_or(&encoded);
                parse_tst_info_imprint(tst)
            })
        });
    let imprint_json = imprint.as_ref().map(|(algorithm, expected)| {
        let calculated = digest_bytes(*algorithm, parent_signature);
        json!({
            "algorithm": algorithm.name(),
            "algorithm_oid": algorithm.oid(),
            "expected": hex(expected),
            "calculated_over_parent_signature": hex(&calculated),
            "matches": calculated.as_slice() == expected.as_slice(),
        })
    });
    json!({
        "status": "parsed",
        "content_type_oid": content.content_type.to_string(),
        "encapsulated_content_type_oid": signed.encap_content_info.econtent_type.to_string(),
        "signer_count": signed.signer_infos.0.len(),
        "message_imprint": imprint_json,
        "message_imprint_matches": imprint.as_ref().map(|(algorithm, expected)| digest_bytes(*algorithm, parent_signature).as_slice() == expected.as_slice()),
    })
}

fn parse_tst_info_imprint(bytes: &[u8]) -> Option<(HashAlgorithm, Vec<u8>)> {
    let outer = tlv_content(bytes, 0, 0x30)?;
    let (_, version_end) = tlv_at(outer, 0)?;
    let (_, policy_end) = tlv_at(outer, version_end)?;
    let imprint = tlv_content(outer, policy_end, 0x30)?;
    let algorithm = tlv_content(imprint, 0, 0x30)?;
    let oid = tlv_content(algorithm, 0, 0x06)?;
    let (_, algorithm_end) = tlv_at(imprint, 0)?;
    let digest = tlv_content(imprint, algorithm_end, 0x04)?.to_vec();
    let algorithm = hash_algorithm_from_oid(oid)?;
    (digest.len() == digest_length(algorithm)).then_some((algorithm, digest))
}

fn hash_algorithm_from_oid(oid: &[u8]) -> Option<HashAlgorithm> {
    Some(match oid {
        [0x2b, 0x0e, 0x03, 0x02, 0x1a] => HashAlgorithm::Sha1,
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => HashAlgorithm::Sha256,
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => HashAlgorithm::Sha384,
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => HashAlgorithm::Sha512,
        _ => return None,
    })
}

fn digest_bytes(algorithm: HashAlgorithm, bytes: &[u8]) -> Vec<u8> {
    let mut digest = ImageHasher::new(algorithm);
    digest.update(bytes);
    digest.finish()
}

fn digest_length(algorithm: HashAlgorithm) -> usize {
    match algorithm {
        HashAlgorithm::Sha1 => 20,
        HashAlgorithm::Sha256 => 32,
        HashAlgorithm::Sha384 => 48,
        HashAlgorithm::Sha512 => 64,
    }
}

fn tlv_content(bytes: &[u8], offset: usize, expected_tag: u8) -> Option<&[u8]> {
    let (tag, content_start, end) = tlv_parts(bytes, offset)?;
    (tag == expected_tag).then(|| &bytes[content_start..end])
}

fn tlv_at(bytes: &[u8], offset: usize) -> Option<(u8, usize)> {
    let (tag, _, end) = tlv_parts(bytes, offset)?;
    Some((tag, end))
}

fn tlv_parts(bytes: &[u8], offset: usize) -> Option<(u8, usize, usize)> {
    let tag = *bytes.get(offset)?;
    let first = *bytes.get(offset + 1)?;
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2_usize)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || offset.checked_add(2 + count)? > bytes.len() {
            return None;
        }
        let mut length = 0_usize;
        for byte in &bytes[offset + 2..offset + 2 + count] {
            length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        (length, 2 + count)
    };
    let content = offset.checked_add(header)?;
    let end = content.checked_add(length)?;
    (end <= bytes.len()).then_some((tag, content, end))
}

fn signer_matches(signer: &cms::signed_data::SignerInfo, certificate: &Certificate) -> bool {
    match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(identifier) => {
            certificate.tbs_certificate.issuer == identifier.issuer
                && certificate.tbs_certificate.serial_number == identifier.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(_) => false,
    }
}

fn signer_identifier_json(identifier: &SignerIdentifier) -> Value {
    match identifier {
        SignerIdentifier::IssuerAndSerialNumber(value) => {
            json!({"kind": "issuer_and_serial", "issuer": bounded_display(&value.issuer), "serial": bounded_display(&value.serial_number)})
        }
        SignerIdentifier::SubjectKeyIdentifier(value) => {
            json!({"kind": "subject_key_identifier", "value_hex": hex(value.0.as_bytes())})
        }
    }
}

fn build_embedded_chain(
    signer_index: usize,
    start: Option<usize>,
    certificates: &[&Certificate],
) -> Value {
    let Some(mut current) = start else {
        return json!({"signer_index": signer_index, "status": "signer_certificate_not_found", "certificate_indices": []});
    };
    let mut indices = Vec::new();
    let mut seen = BTreeSet::new();
    let mut complete = false;
    while indices.len() < MAX_EMBEDDED_CERTIFICATES && seen.insert(current) {
        indices.push(current);
        let certificate = certificates[current];
        if certificate.tbs_certificate.subject == certificate.tbs_certificate.issuer {
            complete = true;
            break;
        }
        let Some(next) = certificates.iter().position(|candidate| {
            candidate.tbs_certificate.subject == certificate.tbs_certificate.issuer
        }) else {
            break;
        };
        current = next;
    }
    json!({
        "signer_index": signer_index,
        "status": if complete { "complete_to_embedded_self_signed_certificate" } else { "partial_embedded_chain" },
        "certificate_indices": indices,
        "links": indices.len().saturating_sub(1),
        "cryptographic_link_validation": "reported_by_offline_platform_chain_build_when_supported",
    })
}

fn certificate_json(certificate: &&Certificate) -> Value {
    let certificate = *certificate;
    json!({
        "subject": bounded_display(&certificate.tbs_certificate.subject),
        "issuer": bounded_display(&certificate.tbs_certificate.issuer),
        "serial": bounded_display(&certificate.tbs_certificate.serial_number),
        "not_before": certificate.tbs_certificate.validity.not_before.to_string(),
        "not_after": certificate.tbs_certificate.validity.not_after.to_string(),
        "certificate_signature_algorithm_oid": certificate.signature_algorithm.oid.to_string(),
        "tbs_signature_algorithm_oid": certificate.tbs_certificate.signature.oid.to_string(),
        "public_key_algorithm_oid": certificate.tbs_certificate.subject_public_key_info.algorithm.oid.to_string(),
    })
}

#[cfg(windows)]
fn platform_verify(bytes: &[u8], signer_count: usize) -> Value {
    crate::authenticode_windows::verify(bytes, signer_count)
}
#[cfg(not(windows))]
fn platform_verify(_bytes: &[u8], _signer_count: usize) -> Value {
    platform_unknown("windows_cryptoapi_unavailable_on_this_platform")
}
#[cfg(windows)]
fn platform_verify_nested(bytes: &[u8]) -> Value {
    crate::authenticode_windows::verify_nested(bytes)
}
#[cfg(windows)]
fn platform_chain_certificate(bytes: &[u8]) -> Value {
    crate::authenticode_windows::chain_from_certificate(bytes)
}
#[cfg(not(windows))]
fn platform_chain_certificate(_bytes: &[u8]) -> Value {
    platform_unknown("windows_cryptoapi_unavailable_on_this_platform")
}
#[cfg(not(windows))]
fn platform_verify_nested(_bytes: &[u8]) -> Value {
    platform_unknown("windows_cryptoapi_unavailable_on_this_platform")
}

fn platform_unknown(reason: &str) -> Value {
    json!({
        "cms_signatures": [],
        "chain_build": {"status": "unknown", "reason": reason},
        "publisher_trust": {"status": "unknown", "reason": reason},
        "revocation": {"status": "unknown", "reason": "offline_no_network_revocation"},
        "offline": true,
        "network_access": false,
    })
}

fn verification_value(entry_index: usize, reason: &str) -> Value {
    json!({
        "entry_index": entry_index,
        "image_digest": {"status": "unknown", "reason": reason},
        "cms_signatures": [{"status": "unknown", "reason": reason}],
        "timestamps": [],
        "embedded_chains": [],
        "chain_build": {"status": "unknown", "reason": reason},
        "publisher_trust": {"status": "unknown", "reason": reason},
        "revocation": {"status": "unknown", "reason": "offline_no_network_revocation"},
        "limitations": ["cryptographic_validity_is_not_a_safety_verdict"],
        "safe_file_assessment": {"status": "unknown", "reason": "not_assessed"},
        "safe_file_claim": "not_made",
    })
}

fn verification_unknown(reason: &str) -> EvidenceDraft {
    verification_unknown_at(0, reason)
}
fn verification_unknown_at(entry_index: usize, reason: &str) -> EvidenceDraft {
    EvidenceDraft::observed(
        "pe.authenticode.verification",
        BTreeMap::from([("entry_index".to_owned(), json!(entry_index))]),
        verification_value(entry_index, reason),
    )
}

fn trust_evidence(present: bool, platform: &Value) -> EvidenceDraft {
    EvidenceDraft {
        kind: "pe.authenticode.trust".to_owned(),
        class: ObservationClass::Unknown,
        locator: BTreeMap::new(),
        value: json!({
            "state": platform.pointer("/publisher_trust/status").and_then(Value::as_str).unwrap_or("unknown"),
            "signature_present": present,
            "publisher_trust": platform.get("publisher_trust").cloned().unwrap_or_else(|| json!({"status": "unknown"})),
            "chain_build": platform.get("chain_build").cloned().unwrap_or_else(|| json!({"status": "unknown"})),
            "revocation": platform.get("revocation").cloned().unwrap_or_else(|| json!({"status": "unknown"})),
            "offline_only": true,
            "network_access": false,
            "safety_verdict": "not_made",
            "limitation": "valid_signature_or_trusted_publisher_does_not_mean_the_file_is_safe",
        }),
        preview_text: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn certificate_status(
    offset: u64,
    index: usize,
    table_offset: u32,
    table_size: u32,
    length: u32,
    revision: u16,
    certificate_type: u16,
    structural_status: &str,
    details: Value,
) -> EvidenceDraft {
    EvidenceDraft::observed(
        "pe.authenticode",
        BTreeMap::from([
            ("file_offset".to_owned(), json!(offset)),
            ("entry_index".to_owned(), json!(index)),
        ]),
        json!({
            "present": true, "table_offset": table_offset, "table_size": table_size,
            "entry_index": index, "length": length, "revision": revision,
            "certificate_type": certificate_type, "structural_status": structural_status,
            "pkcs7": details,
        }),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(1024)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn bounded_display(value: &impl Display) -> String {
    let mut rendered = value.to_string();
    if rendered.len() > 1024 {
        let mut boundary = 1024;
        while !rendered.is_char_boundary(boundary) {
            boundary -= 1;
        }
        rendered.truncate(boundary);
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::BigUint;
    use std::io::Write;

    #[test]
    fn spc_digest_parser_is_bounded_and_rejects_malformed_lengths() {
        assert!(parse_spc_indirect_digest(b"not DER").is_none());
        assert!(tlv_parts(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff], 0).is_none());
    }

    #[test]
    fn trust_wording_never_claims_safety() {
        let evidence = trust_evidence(true, &platform_unknown("test"));
        assert_eq!(evidence.class, ObservationClass::Unknown);
        assert_eq!(evidence.value["safety_verdict"], "not_made");
        assert!(
            evidence.value["limitation"]
                .as_str()
                .is_some_and(|value| value.contains("does_not_mean"))
        );
        assert_eq!(evidence.value["offline_only"], true);
        assert_eq!(evidence.value["network_access"], false);
    }

    #[test]
    fn image_digest_excludes_checksum_security_entry_and_certificate_table() {
        let mut directories = [crate::analysis::Directory::default(); 16];
        directories[4] = crate::analysis::Directory {
            rva: 896,
            size: 128,
        };
        let image = Image {
            pe64: true,
            machine: 0x8664,
            image_base: 0x140000000,
            size_of_headers: 512,
            pe_offset: 64,
            checksum_offset: 152,
            security_directory_offset: 232,
            sections: vec![crate::analysis::Section {
                name: ".text".to_owned(),
                virtual_size: 128,
                virtual_address: 0x1000,
                raw_size: 128,
                raw_offset: 512,
                entropy: Some(0.0),
            }],
            directories,
        };
        let original: Vec<u8> = (0..1024).map(|index| (index & 0xff) as u8).collect();
        let digest = |bytes: &[u8]| {
            let mut file = tempfile::tempfile().expect("temporary file");
            file.write_all(bytes).expect("fixture write");
            file.rewind().expect("fixture rewind");
            authenticode_digest(&mut file, bytes.len() as u64, &image, HashAlgorithm::Sha256)
                .expect("image digest")
        };
        let baseline = digest(&original);
        let mut excluded = original.clone();
        excluded[152..156].fill(0x11);
        excluded[232..240].fill(0x22);
        excluded[896..1024].fill(0x33);
        assert_eq!(baseline, digest(&excluded));
        let mut tampered = original;
        tampered[700] ^= 0xff;
        assert_ne!(baseline, digest(&tampered));
    }

    #[test]
    fn rsa_cms_signature_verification_accepts_valid_and_rejects_tampered_content() {
        let modulus = decode_hex(
            "db1ebfc610d7a411fa1887f621e98f7d38674078deea788ecaf624fff4d2f2ce1706c82913174da126e276949cfad0f72e6700f64bb2eff86865910e2bd98276960f097e1c4ee846e9eee09844295887cb034e35d9576728d9254c38d4dece4df87809b8d9eaf4ef0b238669d83456f1db39e3519a4244f4cf2d68b927eec048199525bf45648f35970a7243f29cec4f89483c4bcad05311848960a4956e12ed6d388e0d6ed336470845d22d8f133315c472cd79ede6891461d93717cf77c4da17ce4a5b96ac123c067b0e06885ce33382a6460b9cdbd33d093712aaad0f9de2529ca17fcd22750127f644ba1f5478941a35f3bd4e315dad1cc8d8969a3c11f5",
        );
        let signature = decode_hex(
            "ba74a3e790f14b06e83dc43e48eb4a2cce471a7a99f0d4c5829b9c1725fb32ea281a0eb07db6b5f3a2f18d9199b0adae2c5abcd33d9254e4b0082defd8990c0d02c585a027a727cd9c4781164ffb7b59b5cba3a9285d57fa9791e47d3dab81522cf981905c383f1f91e8312f4afe21e3e85b6a9170fcbee995b10aae0a325b8eb48d7bdabd339cbb4ebfc57fe28f115399c09406da80cfb03baffc524367f30dd569c27c1607c8b2d12edcb2a9d15e9c7f0a9391f22e54164a00406c66fce1464ba8db7cb57d99a0f3b5bf5049f6dcc433cd11e594ef51898752fe14c02d5515c164d2ba818709a965452f65d115ce3f52453c01fe0988fa93a8cbea705ca576",
        );
        let key = RsaPublicKey::new(BigUint::from_bytes_be(&modulus), BigUint::from(65_537_u32))
            .expect("valid public key");
        let message = b"Artifacta deterministic CMS verification fixture";
        assert!(verify_rsa_pkcs1v15(
            &key,
            HashAlgorithm::Sha256,
            message,
            &signature
        ));
        assert!(!verify_rsa_pkcs1v15(
            &key,
            HashAlgorithm::Sha256,
            b"tampered fixture",
            &signature
        ));
    }

    #[test]
    fn restored_self_signed_fixture_has_valid_cms_with_encoded_content_digest() {
        let fixture = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../testfiles/01_signed_selfsigned_valid.exe"),
        )
        .expect("restored signed fixture");
        let pe_offset =
            u32::from_le_bytes(fixture[0x3c..0x40].try_into().expect("PE offset")) as usize;
        let security_directory = pe_offset + 24 + 112 + 4 * 8;
        let table_offset = u32::from_le_bytes(
            fixture[security_directory..security_directory + 4]
                .try_into()
                .expect("offset"),
        ) as usize;
        let certificate_length = u32::from_le_bytes(
            fixture[table_offset..table_offset + 4]
                .try_into()
                .expect("certificate length"),
        ) as usize;
        let content =
            ContentInfo::from_der(&fixture[table_offset + 8..table_offset + certificate_length])
                .expect("fixture CMS content info");
        let signed = SignedData::from_der(&content.content.to_der().expect("signed DER"))
            .expect("fixture signed data");
        let encapsulated = signed
            .encap_content_info
            .econtent
            .as_ref()
            .expect("encapsulated content");
        let signer = signed.signer_infos.0.iter().next().expect("signer");
        let expected = signer
            .signed_attrs
            .as_ref()
            .expect("signed attrs")
            .iter()
            .find(|attribute| attribute.oid.to_string() == OID_MESSAGE_DIGEST)
            .and_then(|attribute| attribute.values.iter().next())
            .and_then(|value| value.to_der().ok())
            .and_then(|der| tlv_content(&der, 0, 0x04).map(ToOwned::to_owned))
            .expect("message digest");
        assert_ne!(
            digest_bytes(HashAlgorithm::Sha256, encapsulated.value()),
            expected
        );
        assert_eq!(
            digest_bytes(
                HashAlgorithm::Sha256,
                &encapsulated.to_der().expect("encoded content")
            ),
            expected
        );
        let certificate = signed
            .certificates
            .as_ref()
            .and_then(|certificates| {
                certificates.0.iter().find_map(|choice| match choice {
                    CertificateChoices::Certificate(certificate) => Some(certificate),
                    CertificateChoices::Other(_) => None,
                })
            })
            .expect("signer certificate");
        let verification = verify_cms_signer(signer, Some(certificate), Some(encapsulated), 0);
        assert_eq!(verification["status"], "valid");
        assert_eq!(verification["content_digest_matches"], true);
        assert_eq!(
            verification["content_digest_encoding"],
            "encoded_content_der"
        );
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty(), "hex input has an even length");
        pairs
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(text, 16).expect("valid hex")
            })
            .collect()
    }
}
