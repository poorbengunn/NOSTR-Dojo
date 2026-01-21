import { sha256 } from '@noble/hashes/sha256';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import type { NostrEvent, UnsignedEvent } from './types.js';

/**
 * Serialize event for ID computation (NIP-01)
 */
export function serializeEvent(event: UnsignedEvent): string {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
}

/**
 * Compute event ID (SHA-256 of serialized event)
 */
export function computeEventId(event: UnsignedEvent): string {
  const serialized = serializeEvent(event);
  const hash = sha256(new TextEncoder().encode(serialized));
  return bytesToHex(hash);
}

/**
 * Verify event signature (Schnorr BIP-340)
 */
export function verifySignature(event: NostrEvent): boolean {
  try {
    const pubkeyBytes = hexToBytes(event.pubkey);
    const sigBytes = hexToBytes(event.sig);
    const idBytes = hexToBytes(event.id);
    
    return schnorr.verify(sigBytes, idBytes, pubkeyBytes);
  } catch {
    return false;
  }
}

/**
 * Validate event structure and cryptographic integrity
 */
export function validateEvent(event: NostrEvent): { valid: boolean; reason?: string } {
  // Check required fields
  if (!event.id || typeof event.id !== 'string' || event.id.length !== 64) {
    return { valid: false, reason: 'invalid id' };
  }
  
  if (!event.pubkey || typeof event.pubkey !== 'string' || event.pubkey.length !== 64) {
    return { valid: false, reason: 'invalid pubkey' };
  }
  
  if (!event.sig || typeof event.sig !== 'string' || event.sig.length !== 128) {
    return { valid: false, reason: 'invalid sig' };
  }
  
  if (typeof event.created_at !== 'number' || event.created_at < 0) {
    return { valid: false, reason: 'invalid created_at' };
  }
  
  if (typeof event.kind !== 'number' || event.kind < 0) {
    return { valid: false, reason: 'invalid kind' };
  }
  
  if (!Array.isArray(event.tags)) {
    return { valid: false, reason: 'invalid tags' };
  }
  
  if (typeof event.content !== 'string') {
    return { valid: false, reason: 'invalid content' };
  }
  
  // Verify ID matches content
  const computedId = computeEventId({
    pubkey: event.pubkey,
    created_at: event.created_at,
    kind: event.kind,
    tags: event.tags,
    content: event.content,
  });
  
  if (computedId !== event.id) {
    return { valid: false, reason: 'id mismatch' };
  }
  
  // Verify signature
  if (!verifySignature(event)) {
    return { valid: false, reason: 'invalid signature' };
  }
  
  return { valid: true };
}

/**
 * Extract tag value by name
 */
export function getTagValue(event: NostrEvent, tagName: string): string | undefined {
  const tag = event.tags.find(t => t[0] === tagName);
  return tag?.[1];
}

/**
 * Extract all values for a tag name
 */
export function getTagValues(event: NostrEvent, tagName: string): string[] {
  return event.tags
    .filter(t => t[0] === tagName)
    .map(t => t[1])
    .filter((v): v is string => v !== undefined);
}

/**
 * Parse 'a' tag reference (kind:pubkey:d-tag)
 */
export function parseATag(aTag: string): { kind: number; pubkey: string; dTag: string } | null {
  const parts = aTag.split(':');
  if (parts.length < 3) return null;
  
  const kind = parseInt(parts[0], 10);
  if (isNaN(kind)) return null;
  
  const pubkey = parts[1];
  if (pubkey.length !== 64) return null;
  
  const dTag = parts.slice(2).join(':');
  
  return { kind, pubkey, dTag };
}
