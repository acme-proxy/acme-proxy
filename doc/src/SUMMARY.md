# Summary

- [Introduction](introduction.md)
  - [Core Concepts & Glossary](core/concepts.md)

# Getting Started
- [Quick Start](getting_started/quick_start.md)
- [Installation](getting_started/installation.md)
- [Trusting the CA](getting_started/trusting_the_ca.md)
- [Deployment](getting_started/deployment.md)
  - [TLS Termination](features/tls_termination.md)

# Core Components
- [Profiles & Routing](core/profiles.md)
- [Signers](signers/index.md)
  - [Local CA](signers/local_ca.md)
    - [Hardware Keys (PKCS#11)](signers/local_ca_hsm.md)
  - [Relay](signers/relay.md)
  - [Custom Script](signers/custom.md)
- [Challenge Validation](challenges/index.md)
  - [HTTP-01](challenges/http_01.md)
  - [DNS-01](challenges/dns_01.md)
  - [TLS-ALPN-01](challenges/tls_alpn_01.md)
- [Filters & Policies](filters/index.md)
  - [Policy: rules and conditions](filters/policy.md)
  - [Checks](filters/checks.md)
  - [Allowed IP](filters/allowed_ip.md)
  - [Path](filters/path.md)
  - [Reverse DNS](filters/reverse_dns.md)
  - [Identifiers](filters/identifiers.md)
  - [EAB](filters/eab.md)
  - [Custom Script](filters/custom.md)
- [IPAM](ipam/index.md)
  - [NetBox](ipam/netbox.md)
  - [phpIPAM](ipam/phpipam.md)
  - [Custom Script](ipam/custom.md)

# Configuration
- [Configuration Reference](configuration/reference.md)
- [Common Scenarios](configuration/scenarios.md)

# ACME Protocol
- [Protocol Support](features/index.md)
  - [External Account Binding (EAB)](features/eab.md)
  - [Key Rollover](features/key_change.md)
  - [Renewal Information (ARI)](features/renewal_info.md)

# Operations
- [Reloading the Configuration](operations/reload.md)
- [Admin CLI](operations/cli.md)
- [Web Admin](operations/webadmin.md)
  - [Users & Sessions](operations/webadmin_users.md)
  - [Customizing the Panel](operations/webadmin_templates.md)
- [Revocation & CRL](operations/revocation.md)
- [Notifications](notifications/index.md)
  - [Custom Templates](notifications/templates.md)
  - [Email](notifications/email.md)
  - [Webhook](notifications/webhook.md)
  - [Custom Script](notifications/custom.md)
- [Audit Trail](operations/audit.md)
- [Monitoring & Observability](operations/monitoring.md)
  - [Grafana Dashboard](operations/grafana.md)
- [Maintenance & Troubleshooting](operations/troubleshooting.md)

# Security
- [Security Model](security/index.md)
- [Hardening Checklist](security/hardening.md)
- [Secret Rotation](security/rotation.md)
- [ASVS 5.0 Assessment](security/asvs.md)

# Developer Documentation
- [Architecture & Design](dev/architecture.md)
- [Architecture Decisions](dev/adr/index.md)
  - [ADR 0001: Before 1.0.0, only the database schema is a compatibility promise](dev/adr/0001-pre-1-0-compatibility.md)
  - [ADR 0002: One binary over a layered workspace of lockstep crates](dev/adr/0002-workspace-layering.md)
  - [ADR 0003: Migrations are append-only and applied only by the schema owners](dev/adr/0003-migrations-frozen-and-explicit.md)
  - [ADR 0004: Row ids are UUID v7 stored as BLOBs, and their type says where they came from](dev/adr/0004-uuid-v7-blob-ids.md)
  - [ADR 0005: A Rust enum owns each vocabulary, and SQL checks only the closed ones](dev/adr/0005-rust-enums-own-the-vocabularies.md)
- [Database Schema](dev/database.md)
- [Custom Plugins Examples](dev/custom_plugins.md)
- [Testing & Coverage](dev/testing.md)
- [Contributing](dev/contributing.md)
