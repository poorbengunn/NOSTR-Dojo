#!/usr/bin/env node

/**
 * Dojo CLI - Test client for NIP-XXX Hierarchical Credentials
 * 
 * Usage:
 *   npx ts-node src/cli.ts schema <schema-file>     # Publish schema
 *   npx ts-node src/cli.ts issue <credential-json>  # Issue credential
 *   npx ts-node src/cli.ts verify <event-id>        # Verify credential
 *   npx ts-node src/cli.ts query <pubkey>           # Query credentials for pubkey
 */

import WebSocket from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import * as readline from 'readline';

const RELAY_URL = process.env.RELAY_URL || 'ws://localhost:8080';

interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

// Generate or load keypair
function generateKeypair(): { privkey: string; pubkey: string } {
  const privkey = bytesToHex(randomBytes(32));
  const pubkey = bytesToHex(schnorr.getPublicKey(privkey));
  return { privkey, pubkey };
}

function serializeEvent(event: Omit<NostrEvent, 'id' | 'sig'>): string {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
}

function signEvent(event: Omit<NostrEvent, 'id' | 'sig'>, privkey: string): NostrEvent {
  const serialized = serializeEvent(event);
  const hash = sha256(new TextEncoder().encode(serialized));
  const id = bytesToHex(hash);
  const sig = bytesToHex(schnorr.sign(hash, privkey));
  
  return { ...event, id, sig };
}

class DojoClient {
  private ws: WebSocket | null = null;
  private pendingRequests = new Map<string, (events: NostrEvent[]) => void>();
  private keypair: { privkey: string; pubkey: string };
  
  constructor() {
    this.keypair = generateKeypair();
    console.log(`[Client] Generated keypair`);
    console.log(`[Client] Public key: ${this.keypair.pubkey}`);
  }
  
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(RELAY_URL);
      
      this.ws.on('open', () => {
        console.log(`[Client] Connected to ${RELAY_URL}`);
        resolve();
      });
      
      this.ws.on('message', (data) => {
        const message = JSON.parse(data.toString());
        this.handleMessage(message);
      });
      
      this.ws.on('error', reject);
      this.ws.on('close', () => console.log('[Client] Disconnected'));
    });
  }
  
  private handleMessage(message: any[]): void {
    const [type] = message;
    
    switch (type) {
      case 'EVENT': {
        const [, subId, event] = message;
        console.log(`[Event] ${event.kind}: ${event.id.slice(0, 8)}...`);
        break;
      }
      case 'OK': {
        const [, eventId, success, reason] = message;
        if (success) {
          console.log(`[OK] Event ${eventId.slice(0, 8)}... accepted`);
        } else {
          console.log(`[REJECTED] ${reason}`);
        }
        break;
      }
      case 'EOSE': {
        const [, subId] = message;
        console.log(`[EOSE] Subscription ${subId} complete`);
        break;
      }
      case 'NOTICE': {
        console.log(`[NOTICE] ${message[1]}`);
        break;
      }
    }
  }
  
  async publishSchema(schema: object, schemaId: string): Promise<string> {
    const event = signEvent({
      pubkey: this.keypair.pubkey,
      created_at: Math.floor(Date.now() / 1000),
      kind: 30100,
      tags: [
        ['d', schemaId],
        ['name', schemaId],
        ['version', '1.0.0'],
      ],
      content: JSON.stringify(schema),
    }, this.keypair.privkey);
    
    this.send(['EVENT', event]);
    return event.id;
  }
  
  async issueCredential(
    recipientPubkey: string,
    schemaRef: string,
    classId: string,
    expiryDays: number | null,
    chainRef?: string
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const credentialId = `cred-${Date.now()}`;
    
    const tags: string[][] = [
      ['d', credentialId],
      ['p', recipientPubkey],
      ['a', schemaRef],
      ['class', classId],
      ['issued', now.toString()],
      ['expires', expiryDays ? (now + expiryDays * 86400).toString() : 'perpetual'],
    ];
    
    if (chainRef) {
      tags.push(['chain', chainRef]);
    }
    
    const event = signEvent({
      pubkey: this.keypair.pubkey,
      created_at: now,
      kind: 30101,
      tags,
      content: JSON.stringify({ notes: 'Issued via CLI' }),
    }, this.keypair.privkey);
    
    this.send(['EVENT', event]);
    return event.id;
  }
  
  async revokeCredential(credentialRef: string, reason: string): Promise<string> {
    const event = signEvent({
      pubkey: this.keypair.pubkey,
      created_at: Math.floor(Date.now() / 1000),
      kind: 30102,
      tags: [
        ['a', credentialRef],
        ['reason', reason],
      ],
      content: '',
    }, this.keypair.privkey);
    
    this.send(['EVENT', event]);
    return event.id;
  }
  
  async queryCredentials(pubkey: string): Promise<void> {
    const subId = `query-${Date.now()}`;
    this.send(['REQ', subId, {
      kinds: [30101],
      '#p': [pubkey],
    }]);
  }
  
  async querySchemas(): Promise<void> {
    const subId = `schemas-${Date.now()}`;
    this.send(['REQ', subId, {
      kinds: [30100],
      limit: 50,
    }]);
  }
  
  private send(message: any[]): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }
  
  close(): void {
    this.ws?.close();
  }
  
  getPubkey(): string {
    return this.keypair.pubkey;
  }
}

// Interactive mode
async function interactive(): Promise<void> {
  const client = new DojoClient();
  await client.connect();
  
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: 'dojo> ',
  });
  
  console.log('\nDojo CLI - NIP-XXX Credential Client');
  console.log('Commands:');
  console.log('  schema <id>              - Create and publish a test schema');
  console.log('  issue <class> <pubkey>   - Issue credential');
  console.log('  revoke <ref> <reason>    - Revoke credential');
  console.log('  query <pubkey>           - Query credentials');
  console.log('  schemas                  - List schemas');
  console.log('  pubkey                   - Show your pubkey');
  console.log('  exit                     - Quit');
  console.log('');
  
  rl.prompt();
  
  rl.on('line', async (line) => {
    const args = line.trim().split(/\s+/);
    const cmd = args[0];
    
    try {
      switch (cmd) {
        case 'schema': {
          const schemaId = args[1] || 'test-schema';
          const testSchema = {
            classes: {
              admin: {
                name: 'Administrator',
                scope: ['moderator', 'member'],
                issued_by: ['root'],
                expiry: { max_days: 365, renewable: true },
                cascade_revoke: false,
              },
              moderator: {
                name: 'Moderator',
                scope: ['member'],
                issued_by: ['admin'],
                expiry: { max_days: 180, renewable: true },
                cascade_revoke: false,
              },
              member: {
                name: 'Member',
                scope: [],
                issued_by: ['admin', 'moderator'],
                expiry: { max_days: 365, renewable: false },
                cascade_revoke: false,
              },
            },
          };
          await client.publishSchema(testSchema, schemaId);
          console.log(`Schema reference: 30100:${client.getPubkey()}:${schemaId}`);
          break;
        }
        
        case 'issue': {
          const classId = args[1];
          const recipient = args[2];
          if (!classId || !recipient) {
            console.log('Usage: issue <class> <pubkey>');
            break;
          }
          // You'd need to provide the proper schema ref
          const schemaRef = `30100:${client.getPubkey()}:test-schema`;
          await client.issueCredential(recipient, schemaRef, classId, 365);
          break;
        }
        
        case 'revoke': {
          const ref = args[1];
          const reason = args.slice(2).join(' ') || 'misconduct';
          if (!ref) {
            console.log('Usage: revoke <credential-ref> <reason>');
            break;
          }
          await client.revokeCredential(ref, reason);
          break;
        }
        
        case 'query': {
          const pubkey = args[1] || client.getPubkey();
          await client.queryCredentials(pubkey);
          break;
        }
        
        case 'schemas': {
          await client.querySchemas();
          break;
        }
        
        case 'pubkey': {
          console.log(client.getPubkey());
          break;
        }
        
        case 'exit':
        case 'quit':
          client.close();
          rl.close();
          process.exit(0);
          break;
        
        default:
          if (cmd) console.log(`Unknown command: ${cmd}`);
      }
    } catch (err) {
      console.error('Error:', err);
    }
    
    rl.prompt();
  });
}

// Main
const command = process.argv[2];

if (!command || command === 'interactive') {
  interactive().catch(console.error);
} else {
  console.log('Usage: npx ts-node src/cli.ts [interactive]');
}
