# Release Readiness Tracking: Utah vs Dakota

This document tracks Utah's release-readiness work compared against Dakota's modern pipeline as reference. Utah retains its Hummingbird bootc/RPM architecture while adopting Dakota's evidence, promotion, ISO, and recovery practices.

## Overview

Utah is an experimental pre-alpha build of Bluefin on Fedora Hummingbird. While Dakota uses BuildStream 2 to assemble Bluefin from source, Utah uses a bootc/RPM architecture. This document tracks the work needed to bring Utah's pipeline and release practices up to par with Dakota's modern approach.

## Dakota Pipeline Reference

Dakota's pipeline consists of:
- **Validation**: `validate.yml` workflow for PR and merge queue checks
- **Building**: `build.yml` for remote execution builds of four x86 variants
- **Publishing**: `publish.yml` for exporting CAS artifacts, publishing tags, signing, and attesting
- **End-to-End Testing**: `e2e.yml` for manual testsuite dispatch
- **Release Execution**: `execute-release.yml` for stable promotions on Mon/Wed/Fri schedule
- **Rollback Procedures**: `rollback-stable.yml` for recovery operations

Key practices Utah should adopt:
- Evidence-based promotion with cryptographic anchoring
- Digest-based tagging and promotion (not mutable tags)
- Cosign keyless OIDC signatures and SLSA build provenance attestations
- Immutable artifact handling
- Clear separation of build vs. publish workflows

## Audit Slices Progress

### Package Contract Issues
- [ ] https://github.com/projectbluefin/utah-packages/issues/22
- [ ] https://github.com/projectbluefin/utah-packages/issues/23
- [ ] https://github.com/projectbluefin/utah-packages/issues/24
- [ ] https://github.com/projectbluefin/utah-packages/issues/25

### Core Infrastructure Issues
- [ ] https://github.com/projectbluefin/utah/issues/11
- [ ] https://github.com/projectbluefin/utah/issues/12
- [ ] https://github.com/projectbluefin/utah/issues/13
- [ ] https://github.com/projectbluefin/utah/issues/14
- [ ] https://github.com/projectbluefin/utah/issues/15
- [ ] https://github.com/projectbluefin/utah/issues/16
- [ ] https://github.com/projectbluefin/utah/issues/17
- [ ] https://github.com/projectbluefin/utah/issues/18
- [ ] https://github.com/projectbluefin/utah/issues/19
- [ ] https://github.com/projectbluefin/utah/issues/20
- [ ] https://github.com/projectbluefin/utah/issues/21
- [ ] https://github.com/projectbluefin/utah/issues/22
- [ ] https://github.com/projectbluefin/utah/issues/23

### Deferred Package Issues
- [ ] https://github.com/projectbluefin/utah/issues/10
- [ ] https://github.com/projectbluefin/utah-packages/issues/19
- [ ] https://github.com/projectbluefin/utah-packages/issues/20
- [ ] https://github.com/projectbluefin/utah-packages/issues/21

## Key Areas for Dakota Alignment

### 1. CI/CD Pipeline Modernization
Utah currently uses a simpler workflow structure compared to Dakota's sophisticated pipeline:
- [ ] Implement separate validate, build, and publish workflows
- [ ] Add remote execution capabilities for builds
- [ ] Integrate CAS (Content Addressable Storage) for artifact management
- [ ] Add cryptographic signing and attestation workflows
- [ ] Implement digest-based tagging instead of mutable tags

### 2. Evidence-Based Promotion
Dakota uses rigorous evidence collection for promotions:
- [ ] Implement end-to-end testing workflows
- [ ] Add verification gates for package, desktop, VM, installer, upgrade, and rollback
- [ ] Create checksummed production ISO verification
- [ ] Establish traceability from testing/stable tags to exact tested digests

### 3. Release Process Maturity
Dakota's release process includes:
- [ ] Scheduled stable promotions (Mon/Wed/Fri)
- [ ] Automated rollback procedures
- [ ] Keyless signature verification with anchored identity regex
- [ ] Immutable artifact promotion by digest

### 4. Security and Provenance
Security practices to adopt:
- [ ] Cosign keyless OIDC signatures
- [ ] SLSA build provenance attestations
- [ ] SBOM generation and attachment
- [ ] Vulnerability scanning integration

## Acceptance Criteria Progress

- [ ] Every linked P0/P1 slice is resolved or has an explicit maintainer-approved exception
- [ ] A Utah image digest passes package, desktop, VM, installer, upgrade, and rollback gates
- [ ] A checksummed production ISO passes offline plain and encrypted installation gates
- [ ] Moving testing/stable tags and published ISO artifacts can be traced to the exact tested digest and workflow run

## Current Status

Triage complete. Awaiting implementation.

## Next Steps

1. Prioritize core infrastructure issues that block pipeline modernization
2. Begin implementing separate validate/build/publish workflows
3. Establish digest-based tagging practices
4. Create end-to-end testing framework
5. Implement cryptographic signing and verification workflows

---
*This document tracks projectbluefin/utah issue #71*