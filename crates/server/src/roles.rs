//! Which of the server's three jobs this process does.
//!
//! One binary, several processes: `acme-proxy serve --role acme,admin,worker`,
//! defaulting to all three. **All-in-one stays the default** — the split is a
//! deployment mode, not a replacement, and a `serve` with no `--role` builds
//! exactly what it always did.
//!
//! What it buys is privilege separation, which is the point for a CA. The
//! `acme` role parses untrusted JWS and CSRs from the internet; the `admin`
//! role holds operator sessions; the `worker` role reaches out to
//! client-chosen hosts, talks to an upstream CA, sends mail, and is the only
//! one holding the CA key. Each can run under its own uid and sandbox.
//!
//! **This is not [`sockets::Role`](super::sockets::Role)**, and the two must
//! not be conflated. That enum names the three *listeners* a process may hold
//! (`acme`, `admin`, `metrics`); this one names the three *jobs* a process may
//! do. `worker` holds no socket at all, and `metrics` is a socket every role
//! may serve rather than a job anybody does — so the sets differ in both
//! directions and one type could not carry both meanings.

use std::fmt;
use std::str::FromStr;

/// One of the three jobs a process may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProcessRole {
    /// Serve ACME to certificate clients: the ACME listener and the root
    /// router. Enqueues work; runs none.
    Acme,
    /// Serve the web admin: `/ui` and `/api`. Enqueues work; runs none.
    Admin,
    /// Drain the job queue. Owns the schema and the first-run material.
    Worker,
}

impl ProcessRole {
    /// Every role, in the order `--role` documents them.
    pub const ALL: [Self; 3] = [Self::Acme, Self::Admin, Self::Worker];

    /// The spelling `--role` takes and every log line carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Acme => "acme",
            Self::Admin => "admin",
            Self::Worker => "worker",
        }
    }
}

impl fmt::Display for ProcessRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ProcessRole {
    type Err = String;

    /// Refuses an unknown value **by name**, listing the three.
    ///
    /// The `AdminRole`/`--status` rule: passing an unrecognised role through
    /// would start a process doing less than the operator asked for, which is
    /// the failure mode a role flag exists to make visible.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "acme" => Ok(Self::Acme),
            "admin" => Ok(Self::Admin),
            "worker" => Ok(Self::Worker),
            other => Err(format!(
                "unknown role `{other}` (expected one of: acme, admin, worker)"
            )),
        }
    }
}

/// The roles one process runs, never empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleSet {
    acme: bool,
    admin: bool,
    worker: bool,
}

impl Default for RoleSet {
    /// All three: what `serve` with no `--role` runs, and what every
    /// deployment before the flag existed ran.
    fn default() -> Self {
        Self {
            acme: true,
            admin: true,
            worker: true,
        }
    }
}

impl RoleSet {
    /// Whether this process runs `role`.
    #[must_use]
    pub fn has(self, role: ProcessRole) -> bool {
        match role {
            ProcessRole::Acme => self.acme,
            ProcessRole::Admin => self.admin,
            ProcessRole::Worker => self.worker,
        }
    }

    /// The roles held, in a stable order, for a log field.
    #[must_use]
    pub fn labels(self) -> Vec<&'static str> {
        ProcessRole::ALL
            .into_iter()
            .filter(|role| self.has(*role))
            .map(ProcessRole::as_str)
            .collect()
    }

    /// Parses a `--role` value: a comma-separated list, or `None` for all
    /// three.
    ///
    /// # Errors
    ///
    /// An unknown role name, or a list that names none — `--role ""` asks for
    /// a process with nothing to do, which is a typo rather than a topology.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        let Some(value) = value else {
            return Ok(Self::default());
        };

        let mut set = Self {
            acme: false,
            admin: false,
            worker: false,
        };
        for name in value.split(',').filter(|name| !name.trim().is_empty()) {
            match name.parse::<ProcessRole>()? {
                ProcessRole::Acme => set.acme = true,
                ProcessRole::Admin => set.admin = true,
                ProcessRole::Worker => set.worker = true,
            }
        }

        if !(set.acme || set.admin || set.worker) {
            return Err("--role names no role (expected one of: acme, admin, worker)".to_string());
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flag_is_every_role() {
        let set = RoleSet::parse(None).unwrap();
        for role in ProcessRole::ALL {
            assert!(set.has(role), "{role} must be on by default");
        }
        assert_eq!(set, RoleSet::default());
    }

    #[test]
    fn a_list_selects_exactly_what_it_names() {
        let set = RoleSet::parse(Some("acme,worker")).unwrap();
        assert!(set.has(ProcessRole::Acme));
        assert!(set.has(ProcessRole::Worker));
        assert!(!set.has(ProcessRole::Admin));
        assert_eq!(set.labels(), vec!["acme", "worker"]);
    }

    #[test]
    fn whitespace_and_repeats_are_tolerated() {
        let set = RoleSet::parse(Some(" admin , admin ,worker")).unwrap();
        assert_eq!(set.labels(), vec!["admin", "worker"]);
    }

    /// The `--status` rule: an unknown value is refused naming itself and the
    /// alternatives, never silently dropped — a process quietly doing less
    /// than asked is the failure this flag exists to prevent.
    #[test]
    fn an_unknown_role_is_refused_by_name() {
        let error = RoleSet::parse(Some("acme,wroker")).unwrap_err();
        assert!(error.contains("wroker"), "{error}");
        assert!(error.contains("acme, admin, worker"), "{error}");
    }

    #[test]
    fn a_list_naming_no_role_is_refused() {
        assert!(RoleSet::parse(Some("")).unwrap_err().contains("no role"));
        assert!(RoleSet::parse(Some(" , ")).unwrap_err().contains("no role"));
    }

    #[test]
    fn every_role_round_trips_through_its_spelling() {
        for role in ProcessRole::ALL {
            assert_eq!(role.as_str().parse::<ProcessRole>().unwrap(), role);
            assert_eq!(role.to_string(), role.as_str());
        }
    }
}
