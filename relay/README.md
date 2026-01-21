# Dojo Relay

NOSTR relay with NIP-XXX Hierarchical Delegated Credentials support.

## Features

- Full NIP-01 relay implementation
- NIP-XXX credential chain verification
- SQLite storage with WAL mode
- Credential indexing for fast lookups
- Schema validation
- Revocation and renewal handling

## Quick Start

```bash
# Install dependencies
npm install

# Development mode (hot reload)
npm run dev

# Production build
npm run build
npm start
```

## Configuration

Environment variables (`.env`):

```env
RELAY_PORT=8080
DB_PATH=./dojo-relay.db
```

## Supported NIPs

- **NIP-01**: Basic protocol flow
- **NIP-09**: Event deletion
- **NIP-11**: Relay information
- **NIP-16**: Event treatment (replaceable)
- **NIP-20**: Command results
- **NIP-33**: Parameterized replaceable events
- **NIP-58**: Badges (base)
- **NIP-XXX**: Hierarchical Delegated Credentials

## NIP-XXX Event Kinds

| Kind | Name | Description |
|------|------|-------------|
| 30100 | Schema Definition | Root authority defines credential tree |
| 30101 | Credential Grant | Issue credential to recipient |
| 30102 | Revocation | Invalidate a credential |
| 30103 | Renewal | Extend credential expiry |

## Usage Example

### 1. Publish a Schema (Root Authority)

```json
{
  "kind": 30100,
  "tags": [
    ["d", "training-certs-2026"],
    ["name", "Training Certifications"],
    ["version", "1.0.0"]
  ],
  "content": "{\"classes\":{\"instructor\":{\"name\":\"Instructor\",\"scope\":[\"trainee\"],\"issued_by\":[\"root\"],\"expiry\":{\"max_days\":365,\"renewable\":true},\"cascade_revoke\":false},\"trainee\":{\"name\":\"Trainee\",\"scope\":[],\"issued_by\":[\"instructor\"],\"expiry\":{\"max_days\":730,\"renewable\":false},\"cascade_revoke\":false}}}"
}
```

### 2. Issue a Credential

```json
{
  "kind": 30101,
  "tags": [
    ["d", "cred-001"],
    ["p", "<recipient-pubkey>"],
    ["a", "30100:<root-pubkey>:training-certs-2026"],
    ["class", "instructor"],
    ["issued", "1737482400"],
    ["expires", "1769018400"]
  ],
  "content": "{\"notes\":\"Certified January 2026\"}"
}
```

### 3. Query Credentials

```json
["REQ", "sub-1", {
  "kinds": [30101],
  "#p": ["<recipient-pubkey>"]
}]
```

## Docker

```bash
# Build
docker build -t dojo-relay ./relay

# Run
docker run -d -p 8080:8080 -v dojo-data:/app/data dojo-relay
```

## Architecture

```
relay/
├── src/
│   ├── index.ts       # Entry point
│   ├── relay.ts       # WebSocket server
│   ├── database.ts    # SQLite storage
│   ├── credentials.ts # NIP-XXX verification
│   ├── crypto.ts      # Schnorr signatures
│   └── types.ts       # TypeScript types
├── package.json
└── tsconfig.json
```

## Verification Algorithm

The relay verifies credential chains by:

1. Checking event signature
2. Validating against schema
3. Checking revocation status
4. Checking expiry (with renewals)
5. Walking the chain to root authority
6. Verifying issuer had authority at issuance time

## License

Public domain.
