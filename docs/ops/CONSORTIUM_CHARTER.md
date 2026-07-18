# AEGIS consortium charter (practical draft)

**Date:** 2026-07-18  
**Status:** governance artifact — **not legal advice**  
**Audience:** consortium operators, security reviewers, and counsel drafting binding agreements

This document describes how a permissioned AEGIS mixnet consortium is **intended** to
operate. It complements technical runbooks ([`consortium_key_ceremony.md`](consortium_key_ceremony.md),
[`health_gossip.md`](health_gossip.md), [`anonymous_reputation.md`](anonymous_reputation.md))
and the honest research backlog [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md).

Binding law, export controls, and data-protection obligations remain **outside** this repo.

---

## 1. Purpose and scope

The consortium runs a **vetted, layered mix relay fleet** that hides relationship
graphs and op-tempo against a global passive adversary (see spec §1–§4). Membership
is **permissioned**: only relays admitted under M-of-N consortium authority signatures
appear in the signed roster consumed by nodes and clients.

This charter covers:

- Who may join and how they are vetted
- How authority keys are custodied (M-of-N ceremony roles)
- Geographic / jurisdictional diversity goals
- Compromise response
- Reputation and admission disputes
- What the codebase **enforces** vs what remains **policy**

---

## 2. Membership classes

| Class | Role | Typical holder |
|-------|------|----------------|
| **Authority trustee** | Holds (or HSM-custodies) an Ed25519 consortium signing key; participates in roster admissions and rotations | National CERT, defense comms agency, audited NGO ops desk |
| **Relay operator** | Runs `aegis-node` on owned infrastructure; maintains link keys, gossip keys, KEM seeds, reputation ledger | Member org with datacenter presence |
| **Observer / auditor** | Read-only access to signed roster, health exports, CT evidence packages; no signing power | Third-party assessor under NDA |
| **Client org** | Uses `aegis-client` against the permissioned path; does not operate relays | Mission partner endpoints |

**Non-members** must not receive roster authority seeds, link PSKs, or Noise static secrets.

---

## 3. Admission and vetting

### 3.1 Application

Prospective relay operators submit:

1. Legal entity and **jurisdiction of operation** (ISO country + primary datacenter region)
2. Intended relay role (guard / mix / exit — exit requires separate approval)
3. Hybrid KEM public commitment (`RelayRecord` fields per [`consortium_key_ceremony.md`](consortium_key_ceremony.md))
4. Operational contacts (24×7 incident channel)
5. Evidence of baseline security posture (SOC2 / ISO27001 / national equivalent — policy-defined minimum)

### 3.2 Vetting checklist (policy)

Trustees verify **before** collecting M signatures:

- [ ] Entity is not on applicable sanctions / denied-party lists (counsel-owned process)
- [ ] Jurisdiction supports lawful operation of encrypted relay infrastructure
- [ ] Operator agrees to consortium SLA (uptime, patch window, log retention limits)
- [ ] KEM commitment matches operator-generated keys (out-of-band fingerprint exchange)
- [ ] No duplicate jurisdiction slot if diversity quota applies (§5)
- [ ] Probationary admission acceptable (reputation floor seeded in ledger — code default)

### 3.3 Technical admission (code)

After M-of-N signatures, operators persist the record:

```text
ThresholdSignedRelayRecord → roster.json → [roster] on every node
```

Nodes **refuse** unsigned roster loads when `allow_unverified_roster = false` and
`authority_pubkeys` are configured (`aegis-topology::RelayRoster`).

Rate limits: default roster admission policy caps new admits (5 / 24h) — tunable in code.

---

## 4. M-of-N ceremony roles

Ceremony produces the Ed25519 keys that sign admissions. See [`consortium_key_ceremony.md`](consortium_key_ceremony.md).

| Role | Responsibility |
|------|----------------|
| **Ceremony chair** | Schedules offline/air-gapped session; publishes `consortium.json` manifest |
| **Trustee i (1…N)** | Generates or HSM-loads authority *i* seed; publishes `authority-i.pub.hex` only |
| **Shamir custodian** (optional) | Holds one GF(256) share per authority seed; no single custodian holds ≥ M shares |
| **Roster publisher** | Collects M signatures on each `RelayRecord`; writes `roster.json` |
| **Node configurator** | Distributes `[roster] authority_pubkeys` + threshold to every `aegis-node` / client |

**Production default:** hardware custody (`CeremonyCustodyMode::Hardware`) — in-tree stub **fail-closed** until PKCS#11 is linked. Lab uses `SoftwareCustodyProvider` / `aegis-ceremony` helper only.

**Rotation:** generate new N-set → re-sign active relays → update all nodes → retire old pubkeys from `[roster].authority_pubkeys`. No automatic proactive refresh in code.

---

## 5. Jurisdiction diversity goals

Policy targets (adjust per mission; not enforced by cryptography):

| Goal | Example target | Rationale |
|------|----------------|-----------|
| Minimum distinct jurisdictions among **guard** relays | ≥ 3 | Reduces single-nation legal compulsion of entire guard set |
| No single jurisdiction > **40%** of L=4 path slots | cap | Limits geographic correlation attacks |
| Exit concentration | ≤ 1 exit per jurisdiction unless dual-homed approved | Clearnet exit is weaker — diversify deliberately |
| Authority trustees | ≥ 2 jurisdictions represented among N | Prevents single-government roster capture |

The roster `RelayRecord.jurisdiction` field is **declarative** — code stores and displays it;
**compliance with diversity goals is consortium policy**, verified by auditors comparing
roster JSON to charter quotas.

---

## 6. Key compromise response

### 6.1 Authority signing key compromise

1. **Contain:** affected trustee stops signing; notify chair + all operators within policy SLA
2. **Revoke:** remaining trustees publish updated `[roster].authority_pubkeys` excluding compromised key; threshold M may temporarily use N−1 set if pre-agreed
3. **Re-verify:** every node reloads roster with signature verify; reject old admissions signed solely by compromised key if forensic timeline requires re-admission
4. **Rotate:** new ceremony for replacement authority; Shamir shares re-split if used
5. **Post-incident:** document in consortium incident log; optional external audit

**Code enforces:** signature verify on load; cannot load roster signed by unknown keys once pubkeys updated.

**Code does not enforce:** automatic global key revocation broadcast — operators must deploy config.

### 6.2 Relay KEM / link key compromise

1. Operator takes relay offline
2. Trustees issue **revocation** (remove from roster or mark failed in reputation ledger)
3. Neighbors rotate link keys out-of-band; update peer tables
4. Re-admit only after new KEM commitment + vetting repeat if root cause was operator fault

**Code enforces:** peer health gossip → EWMA reputation drain; anomaly-gated admission; optional signed ledger snapshots.

### 6.3 Gossip signing key compromise

Rotate `[health_gossip] signing_seed` and peer `gossip_verifying_key` entries; clear `quorum_log_path` if equivocation suspected.

---

## 7. Reputation dispute process

Anonymous reputation is **Partial** in-tree ([`anonymous_reputation.md`](anonymous_reputation.md)). Disputes span policy + local verifier behavior.

| Stage | Actor | Action |
|-------|-------|--------|
| **1. Local evidence** | Operator | Export signed reputation ledger snapshot + health gossip quorum log excerpt |
| **2. Peer review** | Neighbor operators | Compare median gossip failure rates; check for collusion (K neighbors biased) |
| **3. Consortium panel** | M authorities (policy) | Review admission history, probation scores, anomaly flags — **not** cleartext traffic |
| **4. Remediation** | Trustees + operator | Probation extension, temporary demotion, or roster removal via new M-of-N signed record |
| **5. Appeal** | Operator | Submit counter-evidence within policy window; panel may require third-party auditor |

**Code enforces:** threshold ZK presentation verify + local nullifier replay prevention; signed ledger tamper detection when operator keys configured.

**Code does not enforce:** global reputation consensus, cross-org BFT on scores, or automated dispute arbitration — those are **External** ([`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md) §1).

---

## 8. Code enforces vs policy

| Concern | Enforced in code | Policy / operator only |
|---------|------------------|---------------------------|
| Signed roster admissions | M-of-N verify on load (`ThresholdConsortium`) | Who receives M signatures |
| Unverified roster | Blocked when keys configured + `allow_unverified_roster = false` | Lab exception approval |
| KEM seed handling | External file, DPAPI/keyring, Unix mode `0600` | HSM custody ceremony |
| Link authentication | Noise_IK when static keys configured; identity binding | Key distribution |
| Ingress flood | Token bucket + global cap | Capacity planning |
| Cover egress | Fail-closed when `[cover].require = true` | None — do not disable |
| Health gossip verify | Ed25519 + quorum median merge | Which neighbors in peer table |
| Reputation ledger | EWMA, anomaly gate, optional signed snapshots | Dispute panel outcomes |
| Jurisdiction diversity | Field stored only | Quota compliance audits |
| Sanctions / legal vetting | — | Counsel process |
| Exit clearnet policy | Exit sink wiring | Acceptable use / logging rules |
| Multi-org BFT reputation | — | **External** |

Run **`aegis-node validate --config <toml>`** before deploy — fails closed on lab flags
(see [`DEPLOYMENT.md`](DEPLOYMENT.md)).

---

## 9. Related documents

- [`consortium_key_ceremony.md`](consortium_key_ceremony.md) — M-of-N key generation
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — production checklist
- [`PILOT.md`](PILOT.md) — pilot packaging and staged rollout
- [`health_gossip.md`](health_gossip.md) — neighbor health quorum
- [`anonymous_reputation.md`](anonymous_reputation.md) — ZK presentation verifier checklist
- [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md) — honest open items

---

## 10. Revision history

| Date | Change |
|------|--------|
| 2026-07-18 | Initial practical draft linked from ops docs |
