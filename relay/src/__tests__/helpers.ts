import { describe, it, expect } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';

// Test utilities for generating valid NOSTR events

export interface Keypair {
  privkey: string;
  pubkey: string;
}

export function generateKeypair(): Keypair {
  const privkey = bytesToHex(randomBytes(32));
  const pubkey = bytesToHex(schnorr.getPublicKey(privkey));
  return { privkey, pubkey };
}

export function serializeEvent(event: {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}): string {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
}

export function signEvent(
  event: {
    pubkey: string;
    created_at: number;
    kind: number;
    tags: string[][];
    content: string;
  },
  privkey: string
): {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
} {
  const serialized = serializeEvent(event);
  const hash = sha256(new TextEncoder().encode(serialized));
  const id = bytesToHex(hash);
  const sig = bytesToHex(schnorr.sign(hash, privkey));
  return { ...event, id, sig };
}

// Schema builder for tests
export function buildSchema(classes: Record<string, {
  name: string;
  scope: string[];
  issued_by: string[];
  max_days: number | null;
  renewable: boolean;
  cascade_revoke: boolean;
}>) {
  const schemaClasses: Record<string, any> = {};
  
  for (const [id, cls] of Object.entries(classes)) {
    schemaClasses[id] = {
      name: cls.name,
      scope: cls.scope,
      issued_by: cls.issued_by,
      expiry: {
        max_days: cls.max_days,
        renewable: cls.renewable,
      },
      cascade_revoke: cls.cascade_revoke,
    };
  }
  
  return { classes: schemaClasses };
}

// Event builders - using relocated kinds (30300 series)
export function createSchemaEvent(
  keypair: Keypair,
  schemaId: string,
  schema: object,
  timestamp?: number
) {
  const now = timestamp ?? Math.floor(Date.now() / 1000);
  return signEvent({
    pubkey: keypair.pubkey,
    created_at: now,
    kind: 30300,  // Was 30100, relocated to avoid NIP-113 collision
    tags: [
      ['d', schemaId],
      ['name', schemaId],
      ['version', '1.0.0'],
    ],
    content: JSON.stringify(schema),
  }, keypair.privkey);
}

export function createCredentialEvent(
  issuerKeypair: Keypair,
  recipient: string,
  schemaRef: string,
  classId: string,
  credentialId: string,
  options: {
    expiryDays?: number | null;
    chainRef?: string;
    timestamp?: number;
  } = {}
) {
  const now = options.timestamp ?? Math.floor(Date.now() / 1000);
  const expiryDays = options.expiryDays ?? 365;
  
  const tags: string[][] = [
    ['d', credentialId],
    ['p', recipient],
    ['a', schemaRef],
    ['class', classId],
    ['issued', now.toString()],
    ['expires', expiryDays === null ? 'perpetual' : (now + expiryDays * 86400).toString()],
  ];
  
  if (options.chainRef) {
    tags.push(['chain', options.chainRef]);
  }
  
  return signEvent({
    pubkey: issuerKeypair.pubkey,
    created_at: now,
    kind: 30301,  // Was 30101, relocated to avoid NIP-113 collision
    tags,
    content: JSON.stringify({ notes: 'Test credential' }),
  }, issuerKeypair.privkey);
}

export function createRevocationEvent(
  revokerKeypair: Keypair,
  credentialRef: string,
  reason: string,
  timestamp?: number
) {
  const now = timestamp ?? Math.floor(Date.now() / 1000);
  return signEvent({
    pubkey: revokerKeypair.pubkey,
    created_at: now,
    kind: 30302,  // Was 30102
    tags: [
      ['a', credentialRef],
      ['reason', reason],
    ],
    content: '',
  }, revokerKeypair.privkey);
}

export function createRenewalEvent(
  renewerKeypair: Keypair,
  credentialRef: string,
  newExpiryDays: number,
  timestamp?: number
) {
  const now = timestamp ?? Math.floor(Date.now() / 1000);
  return signEvent({
    pubkey: renewerKeypair.pubkey,
    created_at: now,
    kind: 30303,  // Was 30103
    tags: [
      ['a', credentialRef],
      ['expires', (now + newExpiryDays * 86400).toString()],
    ],
    content: '',
  }, renewerKeypair.privkey);
}

// Time helpers
export function daysAgo(days: number): number {
  return Math.floor(Date.now() / 1000) - (days * 86400);
}

export function daysFromNow(days: number): number {
  return Math.floor(Date.now() / 1000) + (days * 86400);
}

// Basic sanity tests for test utilities
describe('Test Utilities', () => {
  it('generates valid keypairs', () => {
    const kp = generateKeypair();
    expect(kp.privkey).toHaveLength(64);
    expect(kp.pubkey).toHaveLength(64);
  });
  
  it('signs events correctly', () => {
    const kp = generateKeypair();
    const event = signEvent({
      pubkey: kp.pubkey,
      created_at: Math.floor(Date.now() / 1000),
      kind: 1,
      tags: [],
      content: 'test',
    }, kp.privkey);
    
    expect(event.id).toHaveLength(64);
    expect(event.sig).toHaveLength(128);
    
    // Verify signature
    const valid = schnorr.verify(
      hexToBytes(event.sig),
      hexToBytes(event.id),
      hexToBytes(event.pubkey)
    );
    expect(valid).toBe(true);
  });
});
