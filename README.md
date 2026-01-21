# NOSTR Dojo

Research and development repository for NOSTR protocol extensions, focusing on:

- **Hierarchical Delegated Credentials** — NIP extending badges with credential chains, expiry, revocation, and delegated issuance authority
- **Web of Trust** — Trust graph implementations and scoring algorithms
- **IoT/M2M** — Machine identity and authenticated sensor data patterns

## Structure

```
NOSTR-Dojo/
├── nips/                    # Draft NIP specifications
│   └── nip-xxx-hierarchical-credentials.md
├── lib/                     # Reference implementations (planned)
│   ├── schema.ts
│   ├── issue.ts
│   ├── verify.ts
│   └── revoke.ts
├── examples/                # Example schemas (planned)
└── README.md
```

## NIP-XXX: Hierarchical Delegated Credentials

Extends NIP-58 badges to support credential chains where holding a credential confers authority to issue downstream credentials.

**Key features:**
- Credential schemas define hierarchies (root → assessor → practitioner → apprentice)
- Delegating credentials grant issuance scope
- Expiry with optional renewal
- Revocation with optional cascade
- Chain verification back to root authority

**Event kinds:**
| Kind | Purpose |
|------|--------|
| 30100 | Schema Definition |
| 30101 | Credential Grant |
| 30102 | Revocation |
| 30103 | Renewal |

See [nips/nip-xxx-hierarchical-credentials.md](nips/nip-xxx-hierarchical-credentials.md) for full specification.

## Status

🔨 **Draft** — Pre-implementation. Seeking feedback before building reference implementation.

## Related

- [NIP-58: Badges](https://github.com/nostr-protocol/nips/blob/master/58.md)
- [NOSTR Protocol](https://github.com/nostr-protocol/nostr)

## License

Public domain.