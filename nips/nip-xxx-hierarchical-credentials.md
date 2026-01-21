# NIP-XXX: Hierarchical Delegated Credentials

`draft` `optional`

## Abstract

Extends NIP-58 badges to support **credential chains** where holding a credential confers authority to issue downstream credentials. Adds expiry, revocation, and scope constraints.

---

## Terminology

| Term | Definition |
|------|------------|
| **Root Authority** | npub that defines and governs a credential schema |
| **Schema** | Tree structure defining credential classes and their relationships |
| **Credential Class** | A type of credential within a schema (e.g., "Assessor", "Practitioner") |
| **Issuer** | npub holding a credential with issuance scope |
| **Recipient** | npub receiving a credential |
| **Scope** | Which credential classes an issuer can grant |
| **Chain** | Linked sequence of credentials from recipient back to root |
| **Terminal Credential** | Credential with no issuance scope |
| **Delegating Credential** | Credential that grants issuance authority |

---

## Credential Hierarchy Pattern

```
Root Authority
  └─ Level 0: Schema Governance (implicit)
       └─ Level 1: Delegating Credential (can issue L2)
            └─ Level 2: Delegating Credential (can issue L3)
                 └─ Level 3: Terminal Credential (no issuance rights)
```

**Principle:** Authority flows downward. Each level can only issue credentials within its defined scope. Verification walks the chain upward to root.

**Maximum Chain Depth:** 5 levels (to prevent DoS via deep chains).

---

## Event Kinds

| Kind | Name | Purpose |
|------|------|--------|
| 30300 | Schema Definition | Root defines credential tree |
| 30301 | Credential Grant | Issue credential to recipient |
| 30302 | Revocation | Invalidate a credential |
| 30303 | Renewal | Extend expiry of existing credential |

**Reserved for Access Control Layer:**

| Kind | Name | Purpose |
|------|------|--------|
| 30304 | Resource Definition | Define protected resources |
| 30305 | Access Policy | Define access rules |
| 30306 | Trust Endorsement | Bridge social graph to credentials |
| 30307 | Access Audit | Log access attempts (persistent) |

> **Note:** Kinds 30300-30303 were chosen to avoid collision with NIP-113 Activity Events (which uses 30100-30101) and Yakihonne client (which uses 30100 for topic preferences).

---

## Schema Definition (kind: 30300)

Root authority publishes the credential structure:

```json
{
  "kind": 30300,
  "pubkey": "<root-authority>",
  "tags": [
    ["d", "<schema-identifier>"],
    ["name", "<human-readable schema name>"],
    ["version", "<semver>"]
  ],
  "content": "<JSON schema object>"
}
```

### Schema Content Structure

```json
{
  "classes": {
    "<class-id>": {
      "name": "<display name>",
      "description": "<purpose>",
      "scope": ["<class-id>", ...],
      "issued_by": ["root"] | ["<class-id>", ...],
      "expiry": {
        "max_days": <int> | null,
        "renewable": <bool>
      },
      "cascade_revoke": <bool>,
      "constraints": {}
    }
  }
}
```

### Field Definitions

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable credential name |
| `description` | No | Purpose and requirements |
| `scope` | Yes | Array of class-ids this credential can issue. Empty = terminal |
| `issued_by` | Yes | Who can issue. `["root"]` = root only. Otherwise array of class-ids |
| `expiry.max_days` | Yes | Maximum validity period. `null` = perpetual |
| `expiry.renewable` | Yes | Whether credential can be renewed |
| `cascade_revoke` | Yes | If revoked, revoke all downstream credentials |
| `constraints` | No | Schema-specific restrictions (geographic, numeric limits, etc.) |

### Example Schema

```json
{
  "classes": {
    "assessor": {
      "name": "Assessor",
      "description": "Can train and certify practitioners",
      "scope": ["practitioner", "apprentice"],
      "issued_by": ["root"],
      "expiry": { "max_days": 365, "renewable": true },
      "cascade_revoke": false
    },
    "practitioner": {
      "name": "Practitioner",
      "description": "Qualified to practice and supervise apprentices",
      "scope": ["apprentice"],
      "issued_by": ["assessor"],
      "expiry": { "max_days": 730, "renewable": true },
      "cascade_revoke": false
    },
    "apprentice": {
      "name": "Apprentice",
      "description": "In training, must work under supervision",
      "scope": [],
      "issued_by": ["assessor", "practitioner"],
      "expiry": { "max_days": 365, "renewable": false },
      "cascade_revoke": false
    }
  }
}
```

---

## Credential Grant (kind: 30301)

```json
{
  "kind": 30301,
  "pubkey": "<issuer>",
  "created_at": <timestamp>,
  "tags": [
    ["d", "<unique-credential-id>"],
    ["p", "<recipient>"],
    ["a", "30300:<root>:<schema-id>", "<relay-hint>"],
    ["class", "<class-id>"],
    ["issued", "<unix-timestamp>"],
    ["expires", "<unix-timestamp>"] | ["expires", "perpetual"],
    ["chain", "30301:<upstream-issuer>:<upstream-credential-id>", "<relay-hint>"]
  ],
  "content": "<optional JSON: restrictions, notes, evidence>"
}
```

### Tag Definitions

| Tag | Required | Description |
|-----|----------|-------------|
| `d` | Yes | Unique identifier for this credential |
| `p` | Yes | Recipient pubkey |
| `a` | Yes | Reference to schema (kind:pubkey:d-tag) |
| `class` | Yes | Credential class from schema |
| `issued` | Yes | Issuance timestamp |
| `expires` | Yes | Expiry timestamp or "perpetual" |
| `chain` | Conditional | Reference to issuer's credential. Omit if issuer is root |

### Content Structure (optional)

```json
{
  "restrictions": ["<constraint>", ...],
  "evidence": "<URI or hash of supporting documentation>",
  "notes": "<issuer remarks>"
}
```

---

## Revocation (kind: 30302)

```json
{
  "kind": 30302,
  "pubkey": "<revoking-authority>",
  "created_at": <timestamp>,
  "tags": [
    ["a", "30301:<issuer>:<credential-id>", "<relay-hint>"],
    ["reason", "<code>"]
  ],
  "content": "<optional explanation>"
}
```

### Revocation Authority

A credential may be revoked by:
1. Original issuer
2. Any upstream issuer in the chain
3. Root authority

### Reason Codes

| Code | Meaning |
|------|--------|
| `superseded` | Replaced by new credential |
| `withdrawn` | Voluntary surrender |
| `expired` | Administrative cleanup |
| `misconduct` | Violation of terms |
| `fraud` | Credential obtained improperly |
| `upstream` | Issuer's credential revoked (cascade) |

### Cascade Revocation

If `cascade_revoke: true` in schema, revoking a delegating credential triggers revocation of all downstream credentials. Implementation:

1. Query all kind:30301 where `chain` references revoked credential
2. Publish kind:30302 for each with reason `upstream`
3. Recurse for any delegating credentials found

---

## Renewal (kind: 30303)

```json
{
  "kind": 30303,
  "pubkey": "<renewing-authority>",
  "created_at": <timestamp>,
  "tags": [
    ["a", "30301:<original-issuer>:<credential-id>", "<relay-hint>"],
    ["expires", "<new-unix-timestamp>"]
  ],
  "content": "<optional renewal notes>"
}
```

### Renewal Authority

Same as issuance authority for that credential class. Issuer need not be original issuer.

### Constraints

- New expiry must not exceed `max_days` from renewal date
- Cannot renew if `renewable: false` in schema
- Cannot renew revoked credentials

---

## Verification

### Algorithm

```
VERIFY(credential) → VALID | INVALID | EXPIRED | REVOKED

1. Fetch credential event
2. Verify signature
3. Fetch schema from 'a' tag
4. Check class exists in schema

5. Check revocation:
   - Query kind:30302 referencing this credential
   - If found: RETURN REVOKED

6. Check expiry:
   - Get latest kind:30303 renewal (if any)
   - effective_expiry = renewal.expires OR credential.expires
   - If effective_expiry < now AND effective_expiry != "perpetual":
     RETURN EXPIRED

7. Validate issuance authority:
   - Get class definition from schema
   - If "root" in issued_by AND issuer == root:
     RETURN VALID
   - Else:
     - Fetch issuer's credential from 'chain' tag
     - Check issuer's class has this class in scope
     - Check issuer's credential was valid at issuance time:
       - issuer_credential.issued <= credential.issued
       - issuer_credential.expires >= credential.issued (or perpetual)
     - Check chain depth <= 5 (DoS protection)
     - RETURN VERIFY(issuer_credential)  // recurse
```

### Validity at Time of Issuance

Critical: A credential is valid if the issuer held valid authority **at the moment of issuance**. Subsequent expiry or revocation of issuer's credential does not automatically invalidate downstream credentials unless `cascade_revoke: true`.

---

## Client Behavior

### Display

- Show credential class, issuer, expiry
- Indicate chain depth (e.g., "2 links to root")
- Visual distinction for terminal vs delegating credentials
- Warning states: expiring soon, revoked, broken chain

### Caching

- Cache full chain for offline verification
- Refresh revocation status on reconnect
- Store schema locally; check version on sync

### Issuance UI

- Only show credential classes within user's scope
- Enforce max_days constraint on expiry picker
- Require chain reference for non-root issuers

---

## Security Considerations

| Threat | Mitigation |
|--------|------------|
| Forged credentials | Signature verification; chain to known root |
| Revocation hiding | Query multiple relays; timestamp ordering |
| Replay attacks | Unique `d` tag per credential |
| Schema tampering | Replaceable event; clients pin trusted version |
| Chain forgery | Full chain verification to root |
| Time manipulation | Relay timestamps; client sanity checks |
| DoS via deep chains | Maximum chain depth of 5 |

---

## Backward Compatibility

- New event kinds; no conflict with NIP-58 or NIP-113
- Clients unaware of 30300-30303 ignore them
- Credentials function as enhanced badges for legacy clients

---

## Reference Implementation

See `/relay` directory in this repository.

---

## Copyright

This NIP is placed in the public domain.
