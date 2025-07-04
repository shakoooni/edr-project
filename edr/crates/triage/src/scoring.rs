//! Risk scoring engine: deterministic, explainable, zero-unsafe

#[derive(Debug, Clone, Default)]
pub struct RiskFactors {
    pub high_entropy: bool,
    pub is_anonymous: bool,
    pub has_pe_header: bool,
    pub contains_syscalls: bool,
    pub has_no_backing_file: bool,
    pub diffed_from_last_scan: bool,
    pub compressed_entropy_score: f32,
}

pub fn score(f: &RiskFactors) -> u32 {
    let mut s = 0u32;
    if f.high_entropy { s += 30; }
    if f.is_anonymous { s += 10; }
    if f.has_pe_header { s += 20; }
    if f.contains_syscalls { s += 15; }
    if f.diffed_from_last_scan { s += 10; }
    s += f.compressed_entropy_score.min(20.0) as u32;
    s
}

pub fn classify(score: u32) -> &'static str {
    match score {
        0..=49 => "benign",
        50..=80 => "suspicious",
        _ => "likely malicious",
    }
}
