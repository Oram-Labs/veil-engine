use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use regex::Regex;

use super::{builtin, Candidate, Detector, P_IP};
use crate::kind::kinds::IP;

static V4: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("valid IPv4 regex"));
static V6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:[0-9a-f]{1,4}:|::)(?:[0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}(?:%[0-9a-z]+)?")
        .expect("valid IPv6 regex")
});

pub(super) struct Ip {
    pub include_private: bool,
}

impl Ip {
    fn keep(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() || ip.is_unspecified() {
            return false;
        }
        let private = match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_broadcast(),
            IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
        };
        self.include_private || !private
    }
}

impl Detector for Ip {
    fn find(&self, text: &str, out: &mut Vec<Candidate>) {
        for m in V4.find_iter(text) {
            let before = text[..m.start()].chars().next_back();
            let after = &text[m.end()..];
            // Skip version numbers such as v1.2.3.4 and 1.2.3.4.5.
            if matches!(before, Some('.' | 'v' | 'V'))
                || after.starts_with('.') && after[1..].starts_with(|c: char| c.is_ascii_digit())
            {
                continue;
            }
            if let Ok(ip) = m.as_str().parse::<Ipv4Addr>() {
                if self.keep(IpAddr::V4(ip)) {
                    out.push(builtin(m.start(), m.end(), IP, P_IP));
                }
            }
        }
        for m in V6.find_iter(text) {
            let before = text[..m.start()].chars().next_back();
            if before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == ':') {
                continue;
            }
            let s = m.as_str().trim_end_matches(':');
            let after = text[m.start() + s.len()..].chars().next();
            if after.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            let addr = s.split('%').next().unwrap_or(s);
            if addr.matches(':').count() < 2 || looks_like_code(addr) {
                continue;
            }
            if let Ok(ip) = addr.parse::<Ipv6Addr>() {
                if self.keep(IpAddr::V6(ip)) {
                    out.push(builtin(m.start(), m.start() + s.len(), IP, P_IP));
                }
            }
        }
    }
}

/// Paths in code, such as `Outcome::Error` cut down to `e::E`, parse as
/// compressed IPv6. Real addresses are written in one case, and a compressed
/// one nearly always has a group of 3 or 4 digits (`fe80::1`, `2001:db8::1`).
fn looks_like_code(addr: &str) -> bool {
    let letters = || addr.chars().filter(char::is_ascii_alphabetic);
    let mixed_case = letters().any(|c| c.is_ascii_lowercase()) && letters().any(|c| c.is_ascii_uppercase());
    let short_groups = addr.contains("::") && addr.split(':').all(|g| g.len() < 3);
    mixed_case || short_groups
}
