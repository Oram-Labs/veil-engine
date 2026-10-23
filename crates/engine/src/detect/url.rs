use std::sync::LazyLock;

use regex::Regex;

use super::{builtin, Candidate, Detector, P_URL};
use crate::kind::kinds::URL;

static PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s<>"'`\\]+"#).expect("valid URL regex"));

pub(super) struct Url;

impl Detector for Url {
    fn find(&self, text: &str, out: &mut Vec<Candidate>) {
        for m in PATTERN.find_iter(text) {
            let mut s = m.as_str();
            // Drop sentence punctuation and unbalanced closing brackets at the end.
            loop {
                let trimmed = s.trim_end_matches(['.', ',', ';', ':', '!', '?']);
                let trimmed = match trimmed.chars().last() {
                    Some(c @ (')' | ']' | '}')) => {
                        let open = match c {
                            ')' => '(',
                            ']' => '[',
                            _ => '{',
                        };
                        if trimmed.matches(open).count() < trimmed.matches(c).count() {
                            &trimmed[..trimmed.len() - 1]
                        } else {
                            trimmed
                        }
                    }
                    _ => trimmed,
                };
                if trimmed.len() == s.len() {
                    break;
                }
                s = trimmed;
            }
            if s.len() > "https://".len() && !is_loopback(s) {
                out.push(builtin(m.start(), m.start() + s.len(), URL, P_URL));
            }
        }
    }
}

/// Links to this machine (localhost, 127.x, [::1]) point nowhere private.
fn is_loopback(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => host.split(':').next().unwrap_or_default(),
    };
    host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::is_loopback;

    #[test]
    fn loopback_hosts() {
        for yes in [
            "http://localhost:8080",
            "http://LOCALHOST/x",
            "http://127.0.0.1:9/a",
            "http://[::1]:80/",
            "http://app.localhost",
        ] {
            assert!(is_loopback(yes), "{yes}");
        }
        for no in ["https://example.com", "http://10.0.0.1", "https://localhost.example.com", "https://user@host.io"] {
            assert!(!is_loopback(no), "{no}");
        }
    }
}
