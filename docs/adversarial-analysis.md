# Critical Adversarial Analysis: NIP-XXX Hierarchical Delegated Credentials

*White-hat review conducted 2026-01-21*

---

## Executive Summary

The proposed Hierarchical Delegated Credentials NIP faces **fatal conflicts** that would likely prevent adoption. Most critically, **kind 30100 is already in use** by NIP-113 Activity Events and the Yakihonne client, and **kind 20100 falls in NOSTR's ephemeral event range**, meaning relays won't store access audit events. Beyond these technical collisions, the proposal conflicts fundamentally with NOSTR's philosophy—the closest precedent, NIP-26 (Delegated Event Signing), has been explicitly marked **"unrecommended: adds unnecessary burden for little gain"** and a core developer proposed deprecating it entirely.

This analysis identifies **23 significant issues** across six categories that could kill or require major revision of this proposal.

---

## 1. Event Kind Collisions — FATAL

### Kind 30100 is actively used in production

The Yakihonne client has been publishing kind 30100 events since 2023-2024 for topic preference lists (e.g., `MyFavoriteTopicsInYakihonne`). NIP-113 (Activity Events) formalizes this usage in a draft PR (#1423). Additionally, kind **30101 is proposed for Activity Summaries** in the same specification.

### Kind 20100 sits in the ephemeral event range (20000-29999)

Per NIP-01, relays are not expected to store ephemeral events—they're fire-and-forget. Using this for access attempt audit logs defeats the audit trail purpose entirely. Events would disappear after delivery.

| Proposed Kind | Conflict Status | Resolution Required |
|--------------|-----------------|-------------------|
| 30100 (Schema) | **ACTIVE COLLISION** | Must change |
| 30101 (Grant) | Proposed Activity Summaries | High risk |
| 30102-30106 | No known conflicts | Verify before use |
| 20100 (Audit) | **Wrong event class** | Must use 30xxx range |

**Recommendation:** Relocate to an unallocated range such as **30300-30306** for parameterized replaceable events, and use a **10xxx or 30xxx kind** for audit events that require persistence.

---

## 2. NIP-26 Precedent — Community Already Rejected Similar Complexity

The NOSTR community has already rejected similar complexity. NIP-26 attempted single-level delegation and now carries the explicit warning: **"unrecommended: adds unnecessary burden for little gain."**

Key developer statements:

> "This is why NIP-26 is terribly bad; it's radically incomplete and every attempt to fix it increases its complexity and centralization forces exponentially." —GitHub PR #793

> "No one implements NIP-26 and why I proposed to deprecate it entirely." —vitorpamplona, PR #1482

> "Complexity goes through the roof...significantly increases the startup time of any Nostr project." —PR #1482

The proposed credential system is **substantially more complex** than NIP-26: seven new event kinds versus one, multi-hop chains versus single delegation, plus an entire access control layer. If single-level delegation was deemed too burdensome, hierarchical delegation chains face near-certain rejection.

**NIP-41 (Key Rotation/Identity Management)** suffered similarly—described as a "more complete and complex identity management solution," it failed to gain traction.

---

## 3. Existing NIPs Create Overlapping Functionality

### NIP-85 Trusted Assertions (PR #1534)

This active proposal uses **kind 30382** for assertions about entities, enabling service providers to publish trust metrics. Significant overlap exists:

- Both deal with assertions about pubkeys
- Both establish verification chains (NIP-85 via kind 10040 "Authorization" events)
- Could conflict for "verified status" use cases

### NIP-58 Badges — Relationship Undefined

The proposal claims NIP-58 is inadequate but provides no migration path. Current badge structure:

- Kind 30009: Badge Definition (updatable)
- Kind 8: Badge Award (immutable, **no revocation**)
- Kind 30008: Profile Badges (user acceptance)

Badge awards are explicitly designed as immutable—adding revocation fundamentally changes the social contract. The proposal must specify:
- How existing badges translate to credentials
- Dual-system interoperability period
- Client-side graceful degradation

### External Credential Systems Offer Alternatives

| System | Delegation | Revocation | NOSTR Compatibility |
|--------|-----------|------------|-------------------|
| **UCAN** | JWT chains, unlimited depth | CID blacklisting | High (public-key native) |
| **did:nostr** | DID controller model | VC status lists | Draft spec exists |
| **Biscuit** | Datalog rules | Policy-based | Medium (complexity) |
| **NIP-101** | Kind 30503 VCs | W3C compatible | External proposal |

**UCAN** (User Controlled Authorization Networks) presents particularly strong competition: it uses public-key cryptography like NOSTR, supports offline verification, has active implementations (Storacha, NFT.Storage), and already has tooling. The proposal should justify why NOSTR-native events are preferable to embedding UCAN tokens.

---

## 4. Security Vulnerabilities — Fundamental Redesign Required

### Revocation Propagation is Fatally Flawed

NOSTR's relay architecture provides **no guaranteed propagation timing**. The attack window for revoked credentials is:

```
Window = Detection_Time + Publish_Time + Propagation_Time + Cache_TTL
```

In practice, this could be **hours to days**. The 2025 paper "Not in The Prophecies: Practical Attacks on Nostr" (IEEE EuroS&P) confirmed that "relays can lie about data published by others."

**Specific attack:** A credential is revoked on Relay A. Malicious Relay B deliberately hides the revocation event. A verifier querying only Relay B sees the credential as valid. There's no protocol mechanism to prevent this.

### Chain Verification Enables DoS Amplification

Chain verification scales **O(d × r × v)** where d=depth, r=relays per hop, v=verifications per event:

| Chain Depth | Events to Fetch | Signature Verifications | Estimated Time |
|-------------|-----------------|------------------------|----------------|
| 3 | 3-9 | 6-18 | 100-300ms |
| 5 | 5-25 | 10-50 | 250-750ms |
| 10 | 10-100 | 20-200 | 500ms-2s |

Attackers can create deliberately deep chains to exhaust verifier resources.

### Root Key Compromise is Catastrophic with No Recovery

When a root key is compromised:
- All credentials under that root become untrusted
- Attackers can issue arbitrary credentials
- No mechanism distinguishes legitimate from malicious pre-detection credentials
- Complete key rotation affects all downstream entities

The proposal defines **no recovery protocol**:
- No threshold signing for root protection
- No key rotation mechanism
- No emergency broadcast for compromise notification
- No credential migration to successor keys

### Sybil Resistance is Absent

Any NOSTR keypair can request credential issuance at zero cost. Without external identity anchoring, attackers can:
- Create thousands of keypairs for credential farming
- Overwhelm trees with fake delegations
- Artificially inflate chains to increase verification costs

---

## 5. Philosophy Conflicts — Deeper Than Implementation

### "No Central Authority" vs Credential Hierarchies

NOSTR's founding vision from fiatjaf: "The simplest open protocol...without the need for any authority to say so." The protocol prioritizes **self-sovereign identity** flowing from cryptographic keys.

Hierarchical credentials inherently create authority structures:
- Root authorities become trust anchors
- Delegation chains encode organizational power
- Revocation authority concentrates control

This contradicts the explicit NOSTR critique of Bluesky's "PLC, a database run by a central entity that can censor at will." A credential root authority has equivalent power over its credential tree.

### "Smart Clients, Dumb Relays" Violated

NOSTR design specifies relays as simple store-and-forward systems. Chain verification pushes significant validation logic onto either:
- **Relays** (violating "dumb relay" principle, creating fragmentation)
- **Clients** (requiring complex verification code, slowing adoption)

### Seven Event Kinds Violates Minimalism

The single new event in NIP-26 was deemed "unnecessary burden." This proposal introduces seven:
- 30100: Schema Definition
- 30101: Credential Grant
- 30102: Revocation
- 30103: Renewal
- 30104: Resource Definition
- 30105: Access Policy
- 20100: Access Attempt

Each kind adds implementation surface for relays and clients. Historical evidence suggests **most would never be implemented** widely.

---

## 6. Critical Gaps

### Privacy Exposure is GDPR-Incompatible

Public credential chains on relays expose complete organizational hierarchies. Any observer can:
- Map authority structures from root to leaves
- Track credential issuance patterns revealing organizational activity
- Identify access relationships through audit events

GDPR requirements **not addressed**:
- Data minimization (Art. 5): Credentials expose more than necessary
- Right to erasure (Art. 17): NOSTR events are immutable
- Purpose limitation: No mechanism restricts credential use contexts

Modern privacy-preserving credentials (BBS+, SD-JWT, AnonCreds) support selective disclosure and zero-knowledge proofs. The proposal includes none of these capabilities.

### Temporal Edge Cases Undefined

- **Clock skew:** No specification for acceptable tolerance
- **"Valid from" vs "signed at" confusion:** No explicit separation
- **Network partition validity:** No "last known good" fallback

### Cross-Schema Interoperability Missing

No protocol exists for:
- Credentials from different schemas to interact
- Trust anchor mechanisms for multi-schema environments
- Schema-level policy statements about external credentials

---

## 7. Summary of Issues

| Issue | Severity | Status |
|-------|----------|--------|
| Kind 30100 collision with Activity Events | **FATAL** | Must relocate |
| Kind 20100 in ephemeral range | **FATAL** | Must change |
| NIP-26 precedent rejection | **CRITICAL** | Needs justification |
| Revocation propagation unreliable | **CRITICAL** | No mitigation designed |
| Root compromise unrecoverable | **CRITICAL** | No protocol defined |
| Philosophy conflict with NOSTR | **CRITICAL** | Needs reframing |
| Privacy exposure (GDPR) | **HIGH** | No privacy layer |
| DoS via chain verification | **HIGH** | No depth limits |
| Clock skew undefined | **HIGH** | No specification |
| Sybil resistance absent | **HIGH** | No mitigation |

---

## 8. Pathways to Potential Acceptance

Despite these challenges, the proposal could succeed with substantial revision:

1. **Radical simplification**: Reduce to 2-3 event kinds maximum. Consider credential + revocation only, client-side access control.

2. **Event kind relocation**: Move to 30300-30306 range, use persistent kind for audit.

3. **Privacy layer**: Add encrypted credential formats using NIP-44 encryption. Define "blind" chains where intermediates are hidden.

4. **Revocation hardening**: Require multi-relay verification quorum. Support signed revocation proofs with timestamps.

5. **Depth limits**: Mandate maximum chain depth (suggest 3-5). Define verification timeouts.

6. **Root resilience**: Require threshold signatures for root authorities. Define key rotation protocol.

7. **UCAN alignment**: Consider embedding UCAN tokens in NOSTR events rather than inventing new semantics. Leverages existing tooling.

8. **NIP-58 bridge**: Define explicit migration path and dual-system operation.

9. **Organic adoption first**: Build working implementations before formal standardization. NIP acceptance criteria require "fully implemented in at least two clients and one relay."

---

## 9. Recommended Next Steps

1. **Immediate:** Relocate event kinds to avoid collisions
2. **Short-term:** Define maximum chain depth and verification timeouts
3. **Medium-term:** Design revocation hardening with multi-relay quorum
4. **Medium-term:** Add privacy layer (NIP-44 encrypted credentials)
5. **Long-term:** Evaluate UCAN integration vs native approach
6. **Long-term:** Build working implementations before NIP submission

---

*Analysis conducted: 2026-01-21*
*Citadel Sigma · The Forge · T3*
