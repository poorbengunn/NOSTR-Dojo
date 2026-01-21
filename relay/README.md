# Dojo Relay

NOSTR relay with NIP-XXX Hierarchical Delegated Credentials support.

## Quick Start

```bash
cd relay
npm install

# Terminal 1 - Start relay
npm run dev

# Terminal 2 - Run CLI client
npm run cli
```

## Features

- Full NIP-01 relay implementation
- NIP-XXX credential chain verification
- SQLite storage with WAL mode
- Interactive CLI for testing
- Docker support

## CLI Commands

```
dojo> schema myschema       # Publish test schema
dojo> issue admin <pubkey>  # Issue credential  
dojo> query <pubkey>        # Query credentials
dojo> schemas               # List all schemas
dojo> revoke <ref> reason   # Revoke credential
dojo> pubkey                # Show your pubkey
dojo> exit
```

## Supported NIPs

| NIP | Description |
|-----|-------------|
| 01 | Basic protocol |
| 09 | Event deletion |
| 11 | Relay info |
| 16 | Replaceable events |
| 33 | Parameterized replaceable |
| 58 | Badges (base) |
| XXX | Hierarchical Credentials |

## NIP-XXX Event Kinds

| Kind | Name |
|------|------|
| 30100 | Schema Definition |
| 30101 | Credential Grant |
| 30102 | Revocation |
| 30103 | Renewal |

## Docker

```bash
docker build -t dojo-relay .
docker run -d -p 8080:8080 -v dojo-data:/app/data dojo-relay
```

## Architecture

```
relay/
├── src/
│   ├── index.ts       # Entry point
│   ├── relay.ts       # WebSocket server
│   ├── database.ts    # SQLite storage
│   ├── credentials.ts # Chain verification
│   ├── crypto.ts      # Schnorr signatures
│   ├── cli.ts         # Test client
│   └── types.ts       # TypeScript types
└── Dockerfile
```

## Example: Full Credential Chain

```bash
# 1. Start relay
npm run dev

# 2. In another terminal, start CLI
npm run cli

# 3. Create schema (you are root authority)
dojo> schema training

# 4. Issue "admin" credential to someone
dojo> issue admin abc123...pubkey...

# 5. Query their credentials
dojo> query abc123...pubkey...
```

## Verification Flow

1. Signature valid?
2. Schema exists?
3. Class exists in schema?
4. Revoked?
5. Expired?
6. Issuer = root? → VALID
7. Else: walk chain to root, verify each link

## License

Public domain.
