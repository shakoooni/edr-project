#![deny(unsafe_code)]
#![deny(missing_docs)]
//! Triage module: risk scoring and region classification.


use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

/// Risk factors for a memory region.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskFactors {
    /// High entropy detected
    pub high_entropy: bool,
    /// Region is anonymous (not backed by file)
    pub is_anonymous: bool,
    /// PE header detected
    pub has_pe_header: bool,
    /// Syscall stubs detected
    pub contains_syscalls: bool,
    /// No backing file
    pub has_no_backing_file: bool,
    /// Region changed since last scan
    pub diffed_from_last_scan: bool,
    /// Entropy score (0.0-8.0 typical, scaled to 0-20)
    pub compressed_entropy_score: f32,
}

/// Risk score result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Total score
    pub score: u32,
    /// Classification
    pub classification: RiskClass,
    /// Factors
    pub factors: RiskFactors,
}

/// Risk classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskClass {
    /// Benign (<50)
    Benign,
    /// Suspicious (50-80)
    Suspicious,
    /// Malicious (>80)
    Malicious,
}

/// Calculate risk score from factors.
pub fn score_factors(f: &RiskFactors) -> RiskScore {
    let mut score = 0u32;
    if f.high_entropy { score += 30; }
    if f.is_anonymous { score += 10; }
    if f.has_pe_header { score += 20; }
    if f.contains_syscalls { score += 15; }
    if f.diffed_from_last_scan { score += 10; }
    // compressed_entropy_score: scale 0-20
    score += f.compressed_entropy_score.round() as u32;
    let classification = if score < 50 {
        RiskClass::Benign
    } else if score <= 80 {
        RiskClass::Suspicious
    } else {
        RiskClass::Malicious
    };
    RiskScore { score, classification, factors: f.clone() }
}

/// Calculate Shannon entropy for a memory region.
pub fn shannon_entropy(data: &[u8]) -> f32 {
    use smallvec::SmallVec;
    let mut counts: SmallVec<[usize; 256]> = SmallVec::from_elem(0, 256);
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f32;
    if len == 0.0 { return 0.0; }
    let mut entropy = 0.0f32;
    for &c in &counts {
        if c == 0 { continue; }
        let p = c as f32 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Calculate SHA256 hash of a memory region.
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
