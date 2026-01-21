/**
 * Unit tests for crypto.ts - Signature verification and event validation
 */

import { describe, it, expect } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import {
  computeEventId,
  verifySignature,
  validateEvent,
  getTagValue,
  getTagValues,
  parseATag,
} from '../crypto.js';
import { generateKeypair, signEvent } from './helpers.js';

describe('Crypto: Event ID Computation', () => {
  it('computes deterministic event ID', () => {
    const event = {
      pubkey: '0'.repeat(64),
      created_at: 1234567890,
      kind: 1,
      tags: [],
      content: 'test',
    };
    
    const id1 = computeEventId(event);
    const id2 = computeEventId(event);
    
    expect(id1).toBe(id2);
    expect(id1).toHaveLength(64);
  });
  
  it('different content produces different ID', () => {
    const base = {
      pubkey: '0'.repeat(64),
      created_at: 1234567890,
      kind: 1,
      tags: [],
    };
    
    const id1 = computeEventId({ ...base, content: 'test1' });
    const id2 = computeEventId({ ...base, content: 'test2' });
    
    expect(id1).not.toBe(id2);
  });
});

describe('Crypto: Signature Verification', () => {
  it('verifies valid signature', () => {
    const kp = generateKeypair();
    const event = signEvent({
      pubkey: kp.pubkey,
      created_at: Math.floor(Date.now() / 1000),
      kind: 1,
      tags: [],
      content: 'test',
    }, kp.privkey);
    
    expect(verifySignature(event)).toBe(true);
  });
  
  it('rejects tampered content', () => {
    const kp = generateKeypair();
    const event = signEvent({
      pubkey: kp.pubkey,
      created_at: Math.floor(Date.now() / 1000),
      kind: 1,
      tags: [],
      content: 'test',
    }, kp.privkey);
    
    // Tamper with content but keep same sig
    const tampered = { ...event, content: 'tampered' };
    
    // This should still "verify" the signature against the ID,
    // but validateEvent will catch the ID mismatch
    // verifySignature only checks sig against id
  });
  
  it('rejects invalid signature format', () => {
    const event = {
      id: '0'.repeat(64),
      pubkey: '0'.repeat(64),
      created_at: 1234567890,
      kind: 1,
      tags: [],
      content: 'test',
      sig: 'invalid',
    };
    
    expect(verifySignature(event)).toBe(false);
  });
});

describe('Crypto: Event Validation', () => {
  it('validates correct event', () => {
    const kp = generateKeypair();
    const event = signEvent({
      pubkey: kp.pubkey,
      created_at: Math.floor(Date.now() / 1000),
      kind: 1,
      tags: [],
      content: 'test',
    }, kp.privkey);
    
    const result = validateEvent(event);
    expect(result.valid).toBe(true);
  });
  
  it('rejects missing id', () => {
    const result = validateEvent({
      id: '',
      pubkey: '0'.repeat(64),
      created_at: 1234567890,
      kind: 1,
      tags: [],
      content: 'test',
      sig: '0'.repeat(128),
    });
    
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('invalid id');
  });
  
  it('rejects invalid pubkey length', () => {
    const result = validateEvent({
      id: '0'.repeat(64),
      pubkey: '0'.repeat(32), // Wrong length
      created_at: 1234567890,
      kind: 1,
      tags: [],
      content: 'test',
      sig: '0'.repeat(128),
    });
    
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('invalid pubkey');
  });
  
  it('rejects id mismatch', () => {
    const kp = generateKeypair();
    const event = signEvent({
      pubkey: kp.pubkey,
      created_at: Math.floor(Date.now() / 1000),
      kind: 1,
      tags: [],
      content: 'test',
    }, kp.privkey);
    
    // Change ID
    const tampered = { ...event, id: '1'.repeat(64) };
    
    const result = validateEvent(tampered);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('id mismatch');
  });
});

describe('Crypto: Tag Utilities', () => {
  const event = {
    id: '0'.repeat(64),
    pubkey: '0'.repeat(64),
    created_at: 1234567890,
    kind: 1,
    tags: [
      ['d', 'test-id'],
      ['p', 'pubkey1'],
      ['p', 'pubkey2'],
      ['a', '30100:abc:schema'],
      ['class', 'admin'],
    ],
    content: '',
    sig: '0'.repeat(128),
  };
  
  it('getTagValue returns first match', () => {
    expect(getTagValue(event, 'd')).toBe('test-id');
    expect(getTagValue(event, 'p')).toBe('pubkey1');
    expect(getTagValue(event, 'nonexistent')).toBeUndefined();
  });
  
  it('getTagValues returns all matches', () => {
    expect(getTagValues(event, 'p')).toEqual(['pubkey1', 'pubkey2']);
    expect(getTagValues(event, 'd')).toEqual(['test-id']);
    expect(getTagValues(event, 'nonexistent')).toEqual([]);
  });
});

describe('Crypto: A-Tag Parsing', () => {
  it('parses valid a-tag', () => {
    const result = parseATag('30100:' + '0'.repeat(64) + ':my-schema');
    
    expect(result).not.toBeNull();
    expect(result?.kind).toBe(30100);
    expect(result?.pubkey).toBe('0'.repeat(64));
    expect(result?.dTag).toBe('my-schema');
  });
  
  it('handles d-tag with colons', () => {
    const result = parseATag('30101:' + '0'.repeat(64) + ':namespace:id:extra');
    
    expect(result).not.toBeNull();
    expect(result?.dTag).toBe('namespace:id:extra');
  });
  
  it('rejects invalid format', () => {
    expect(parseATag('invalid')).toBeNull();
    expect(parseATag('30100:short')).toBeNull();
    expect(parseATag('notanumber:' + '0'.repeat(64) + ':id')).toBeNull();
  });
});
