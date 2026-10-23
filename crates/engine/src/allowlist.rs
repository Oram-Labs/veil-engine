//! Values that must never be redacted.

use std::collections::HashSet;

pub(crate) struct Allowlist {
    exact: HashSet<String>,
    domains: Vec<String>,
}

impl Allowlist {
    pub fn new(entries: &[String]) -> Self {
        let mut exact = HashSet::new();
        let mut domains = Vec::new();
        for e in entries {
            let e = e.trim().to_lowercase();
            if e.is_empty() {
                continue;
            }
            if let Some(d) = e.strip_prefix('@') {
                domains.push(d.to_owned());
            } else if !e.contains('@') && !e.contains('/') && e.contains('.') && !e.contains(' ') {
                // A bare domain also counts as an exact value (e.g. an IP address).
                domains.push(e.clone());
                exact.insert(e);
            } else {
                exact.insert(e);
            }
        }
        Allowlist { exact, domains }
    }

    pub fn allows(&self, value: &str) -> bool {
        let v = value.to_lowercase();
        if self.exact.contains(&v) {
            return true;
        }
        let host = if let Some((_, rest)) = v.split_once("://") {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
            let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            authority.split(':').next().unwrap_or_default()
        } else if let Some((_, domain)) = v.rsplit_once('@') {
            domain
        } else {
            return false;
        };
        self.domains.iter().any(|d| host == d || host.ends_with(&format!(".{d}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_domain_entries() {
        let a = Allowlist::new(&[
            "Support@Acme.com".into(),
            "@acme.org".into(),
            "status.acme.io".into(),
            "10.0.0.1".into(),
        ]);
        assert!(a.allows("support@acme.com"));
        assert!(!a.allows("sales@acme.com"));
        assert!(a.allows("ana@acme.org") && a.allows("ana@eu.acme.org"));
        assert!(!a.allows("ana@notacme.org"));
        assert!(a.allows("https://status.acme.io/incidents?id=1"));
        assert!(a.allows("https://user@status.acme.io:8443/x"));
        assert!(!a.allows("https://acme.io/"));
        assert!(a.allows("10.0.0.1"));
        assert!(!a.allows("10.0.0.2"));
    }
}
