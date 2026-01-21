# Dojo Relay

NOSTR relay with NIP-XXX Hierarchical Delegated Credentials support.

## Quick Start

```bash
cd relay
npm install

# Start relay
npm run dev

# Run CLI client (separate terminal)
npm run cli

# Run tests
npm test
```

## Test Suite

Comprehensive test infrastructure with use-case-driven scenarios:

```bash
npm test                  # Run all tests
npm run test:watch        # Watch mode
npm run test:coverage     # Coverage report
npm run test:training     # Training credentials only
npm run test:iot          # IoT identity only
```

### Test Structure

```
src/__tests__/
├── helpers.ts                    # Test utilities, event builders
├── crypto.test.ts                # Unit: signature verification
├── usecase.training.test.ts      # Use case: Dojo training certs
└── usecase.iot.test.ts           # Use case: IoT device identity
```

### Use Case: Training Credentials (The Dojo)

Tests the Lyceum/Praxis training hierarchy:

```
Citadel (root)
  └─ Course Director (Sean - Director of Praxis)
       └─ Instructor (Alice)
            └─ Trainee (Bob)
```

**Scenarios:**
- ✅ Root issues Course Director credential
- ✅ Course Director issues Instructor credential  
- ✅ Instructor issues Trainee credential
- ✅ Full 3-level chain verification
- ❌ Trainee cannot issue (no scope)
- ❌ Instructor cannot issue Course Director (out of scope)
- ❌ Expired credential rejection
- ❌ Issuer expired at issuance time
- ✅ Credential renewal extends validity
- ❌ Revoked credential rejection
- ✅ Root can revoke any credential in chain

### Use Case: IoT Device Identity (Bryncoch)

Tests device provisioning for site management:

```
Citadel (root)
  └─ Site Controller (Bryncoch)
       ├─ Gateway (local hub)
       │    ├─ Sensor (temperature)
       │    └─ Sensor (humidity)
       └─ Actuator (irrigation)
```

**Scenarios:**
- ✅ Root provisions Site Controller
- ✅ Controller provisions sensors directly
- ✅ Controller → Gateway → Sensor chain
- ❌ Sensor cannot provision other devices
- ❌ Gateway cannot issue site-controller
- ❌ Rogue device without credentials
- ✅ Device replacement (revoke + reissue)
- ✅ Sensor data attestation pattern
- ❌ Cross-site credential rejection

## CLI Commands

```
dojo> schema <id>           # Publish test schema
dojo> issue <class> <pk>    # Issue credential  
dojo> query <pk>            # Query credentials
dojo> schemas               # List all schemas
dojo> revoke <ref> <reason> # Revoke credential
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

## Architecture

```
relay/
├── src/
│   ├── index.ts           # Entry point
│   ├── relay.ts           # WebSocket server
│   ├── database.ts        # SQLite storage
│   ├── credentials.ts     # Chain verification
│   ├── crypto.ts          # Schnorr signatures
│   ├── types.ts           # TypeScript types
│   ├── cli.ts             # Test client
│   └── __tests__/         # Test suite
├── vitest.config.ts
├── Dockerfile
└── package.json
```

## Docker

```bash
docker build -t dojo-relay .
docker run -d -p 8080:8080 -v dojo-data:/app/data dojo-relay
```

## Verification Algorithm

1. Signature valid?
2. Schema exists?
3. Class exists in schema?
4. Revoked? (check kind:30102)
5. Expired? (check renewals kind:30103)
6. Issuer = root? → **VALID**
7. Else: walk chain to root
   - Each link: issuer had valid credential at issuance time
   - Each link: issuer's class has scope to issue this class

## License

Public domain.
