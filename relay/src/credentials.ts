import type { NostrEvent, CredentialSchema, VerificationResult, CredentialRow } from './types.js';
import { EVENT_KINDS } from './types.js';
import { getTagValue, parseATag } from './crypto.js';
import type { EventStore } from './database.js';

/**
 * NIP-XXX Credential Verifier
 * 
 * Validates credential chains back to root authority
 */
export class CredentialVerifier {
  constructor(private store: EventStore) {}
  
  /**
   * Verify a credential event
   */
  verify(credentialEvent: NostrEvent, now: number = Math.floor(Date.now() / 1000)): VerificationResult {
    // Must be a credential grant
    if (credentialEvent.kind !== EVENT_KINDS.CREDENTIAL_GRANT) {
      return { status: 'INVALID', reason: 'not a credential event' };
    }
    
    // Get credential metadata
    const schemaRef = getTagValue(credentialEvent, 'a');
    const classId = getTagValue(credentialEvent, 'class');
    const issuedStr = getTagValue(credentialEvent, 'issued');
    const expiresStr = getTagValue(credentialEvent, 'expires');
    const chainRef = getTagValue(credentialEvent, 'chain');
    
    if (!schemaRef || !classId || !issuedStr) {
      return { status: 'INVALID', reason: 'missing required tags' };
    }
    
    const issuedAt = parseInt(issuedStr, 10);
    const expiresAt = expiresStr === 'perpetual' ? null : parseInt(expiresStr ?? '0', 10) || null;
    
    // Check revocation
    const credRow = this.store.getCredential(credentialEvent.id);
    if (credRow?.revoked) {
      return { 
        status: 'REVOKED', 
        revoked_at: credRow.revoked_at ?? now, 
        reason: credRow.revoke_reason ?? 'unspecified' 
      };
    }
    
    // Check expiry (accounting for renewals via db)
    const effectiveExpiry = credRow?.expires_at ?? expiresAt;
    if (effectiveExpiry !== null && effectiveExpiry < now) {
      return { status: 'EXPIRED', expired_at: effectiveExpiry };
    }
    
    // Fetch and parse schema
    const schema = this.getSchema(schemaRef);
    if (!schema) {
      return { status: 'INVALID', reason: 'schema not found' };
    }
    
    const classDefinition = schema.classes[classId];
    if (!classDefinition) {
      return { status: 'INVALID', reason: 'credential class not found in schema' };
    }
    
    // Parse schema reference to get root pubkey
    const schemaInfo = parseATag(schemaRef);
    if (!schemaInfo) {
      return { status: 'INVALID', reason: 'invalid schema reference' };
    }
    
    const rootPubkey = schemaInfo.pubkey;
    
    // Check if issuer is root
    if (classDefinition.issued_by.includes('root')) {
      if (credentialEvent.pubkey === rootPubkey) {
        return { status: 'VALID', chain_depth: 0 };
      }
    }
    
    // Non-root issuer - must have chain reference
    if (!chainRef) {
      return { status: 'INVALID', reason: 'non-root issuer without chain reference' };
    }
    
    // Verify chain
    return this.verifyChain(
      credentialEvent.pubkey,
      issuedAt,
      classId,
      classDefinition.issued_by,
      chainRef,
      schema,
      rootPubkey,
      now,
      1
    );
  }
  
  /**
   * Recursively verify credential chain
   */
  private verifyChain(
    issuerPubkey: string,
    credentialIssuedAt: number,
    credentialClassId: string,
    allowedIssuers: string[],
    chainRef: string,
    schema: CredentialSchema,
    rootPubkey: string,
    now: number,
    depth: number
  ): VerificationResult {
    // Prevent infinite loops and DoS - max depth of 5
    if (depth > 5) {
      return { status: 'INVALID', reason: 'chain too deep (max 5)' };
    }
    
    // Parse chain reference (30301:pubkey:d-tag)
    const chainInfo = parseATag(chainRef);
    if (!chainInfo || chainInfo.kind !== 30301) {
      return { status: 'INVALID', reason: 'invalid chain reference' };
    }
    
    // Find issuer's credential
    const issuerCredentialEvent = this.findCredentialEvent(chainInfo.pubkey, chainInfo.dTag);
    if (!issuerCredentialEvent) {
      return { status: 'INVALID', reason: 'issuer credential not found' };
    }
    
    // Verify issuer's pubkey matches credential recipient
    const issuerCredentialRecipient = getTagValue(issuerCredentialEvent, 'p');
    if (issuerCredentialRecipient !== issuerPubkey) {
      return { status: 'INVALID', reason: 'chain pubkey mismatch' };
    }
    
    // Get issuer's credential class
    const issuerClassId = getTagValue(issuerCredentialEvent, 'class');
    if (!issuerClassId) {
      return { status: 'INVALID', reason: 'issuer credential missing class' };
    }
    
    // Verify issuer's class is in allowed issuers
    if (!allowedIssuers.includes(issuerClassId)) {
      return { status: 'INVALID', reason: `issuer class '${issuerClassId}' not authorized to issue '${credentialClassId}'` };
    }
    
    // Verify issuer's credential class has scope to issue this class
    const issuerClassDef = schema.classes[issuerClassId];
    if (!issuerClassDef) {
      return { status: 'INVALID', reason: 'issuer class not found in schema' };
    }
    
    if (!issuerClassDef.scope.includes(credentialClassId)) {
      return { status: 'INVALID', reason: `issuer class '${issuerClassId}' lacks scope to issue '${credentialClassId}'` };
    }
    
    // Verify issuer's credential was valid at time of issuance
    const issuerIssuedStr = getTagValue(issuerCredentialEvent, 'issued');
    const issuerExpiresStr = getTagValue(issuerCredentialEvent, 'expires');
    
    if (!issuerIssuedStr) {
      return { status: 'INVALID', reason: 'issuer credential missing issued timestamp' };
    }
    
    const issuerIssuedAt = parseInt(issuerIssuedStr, 10);
    const issuerExpiresAt = issuerExpiresStr === 'perpetual' ? null : parseInt(issuerExpiresStr ?? '0', 10) || null;
    
    // Issuer's credential must have been issued before they issued downstream
    if (issuerIssuedAt > credentialIssuedAt) {
      return { status: 'INVALID', reason: 'issuer credential issued after downstream credential' };
    }
    
    // Issuer's credential must not have been expired at issuance time
    if (issuerExpiresAt !== null && issuerExpiresAt < credentialIssuedAt) {
      return { status: 'INVALID', reason: 'issuer credential was expired at issuance time' };
    }
    
    // Check if issuer's credential is currently revoked
    const issuerCredRow = this.store.getCredential(issuerCredentialEvent.id);
    if (issuerCredRow?.revoked) {
      // Check if revocation happened before the downstream credential was issued
      // If cascade_revoke is true, this would invalidate downstream
      const issuerClassDef2 = schema.classes[issuerClassId];
      if (issuerClassDef2?.cascade_revoke && issuerCredRow.revoked_at && issuerCredRow.revoked_at <= credentialIssuedAt) {
        return { status: 'INVALID', reason: 'issuer credential was revoked (cascade)' };
      }
    }
    
    // Check issuer's upstream chain
    const issuerChainRef = getTagValue(issuerCredentialEvent, 'chain');
    
    // If issuer's class can be issued by root and their issuer is root
    if (issuerClassDef.issued_by.includes('root')) {
      if (issuerCredentialEvent.pubkey === rootPubkey) {
        return { status: 'VALID', chain_depth: depth };
      }
    }
    
    // Continue up the chain
    if (!issuerChainRef) {
      return { status: 'INVALID', reason: 'broken chain - non-root issuer without chain reference' };
    }
    
    return this.verifyChain(
      issuerCredentialEvent.pubkey,
      issuerIssuedAt,
      issuerClassId,
      issuerClassDef.issued_by,
      issuerChainRef,
      schema,
      rootPubkey,
      now,
      depth + 1
    );
  }
  
  /**
   * Find a credential event by issuer pubkey and d-tag
   */
  private findCredentialEvent(pubkey: string, dTag: string): NostrEvent | null {
    const events = this.store.queryEvents({
      kinds: [EVENT_KINDS.CREDENTIAL_GRANT],
      authors: [pubkey],
      '#d': [dTag],
      limit: 1,
    });
    
    return events[0] ?? null;
  }
  
  /**
   * Parse and return schema content
   */
  private getSchema(schemaRef: string): CredentialSchema | null {
    const cached = this.store.getSchema(schemaRef);
    if (!cached) return null;
    
    try {
      return JSON.parse(cached.content) as CredentialSchema;
    } catch {
      return null;
    }
  }
  
  /**
   * Validate a credential grant event before accepting
   */
  validateCredentialGrant(event: NostrEvent): { valid: boolean; reason?: string } {
    const schemaRef = getTagValue(event, 'a');
    const classId = getTagValue(event, 'class');
    const recipient = getTagValue(event, 'p');
    const issuedStr = getTagValue(event, 'issued');
    const expiresStr = getTagValue(event, 'expires');
    const dTag = getTagValue(event, 'd');
    
    // Required tags
    if (!schemaRef) return { valid: false, reason: 'missing schema reference (a tag)' };
    if (!classId) return { valid: false, reason: 'missing class tag' };
    if (!recipient) return { valid: false, reason: 'missing recipient (p tag)' };
    if (!issuedStr) return { valid: false, reason: 'missing issued tag' };
    if (!expiresStr) return { valid: false, reason: 'missing expires tag' };
    if (!dTag) return { valid: false, reason: 'missing d tag' };
    
    // Validate schema exists
    const schema = this.getSchema(schemaRef);
    if (!schema) return { valid: false, reason: 'schema not found' };
    
    // Validate class exists in schema
    const classDef = schema.classes[classId];
    if (!classDef) return { valid: false, reason: `class '${classId}' not found in schema` };
    
    // Validate expiry
    if (expiresStr !== 'perpetual') {
      const expiresAt = parseInt(expiresStr, 10);
      const issuedAt = parseInt(issuedStr, 10);
      
      if (isNaN(expiresAt)) return { valid: false, reason: 'invalid expires timestamp' };
      if (isNaN(issuedAt)) return { valid: false, reason: 'invalid issued timestamp' };
      
      // Check max_days constraint
      if (classDef.expiry.max_days !== null) {
        const maxExpiry = issuedAt + (classDef.expiry.max_days * 86400);
        if (expiresAt > maxExpiry) {
          return { valid: false, reason: `expires exceeds max_days (${classDef.expiry.max_days})` };
        }
      }
    } else if (classDef.expiry.max_days !== null) {
      return { valid: false, reason: 'perpetual not allowed for this class' };
    }
    
    return { valid: true };
  }
  
  /**
   * Validate schema definition
   */
  validateSchema(event: NostrEvent): { valid: boolean; reason?: string } {
    const dTag = getTagValue(event, 'd');
    const nameTag = getTagValue(event, 'name');
    
    if (!dTag) return { valid: false, reason: 'missing d tag' };
    if (!nameTag) return { valid: false, reason: 'missing name tag' };
    
    try {
      const schema = JSON.parse(event.content) as CredentialSchema;
      
      if (!schema.classes || typeof schema.classes !== 'object') {
        return { valid: false, reason: 'schema missing classes object' };
      }
      
      // Validate each class definition
      for (const [classId, classDef] of Object.entries(schema.classes)) {
        if (!classDef.name) {
          return { valid: false, reason: `class '${classId}' missing name` };
        }
        if (!Array.isArray(classDef.scope)) {
          return { valid: false, reason: `class '${classId}' missing scope array` };
        }
        if (!Array.isArray(classDef.issued_by)) {
          return { valid: false, reason: `class '${classId}' missing issued_by array` };
        }
        if (!classDef.expiry || typeof classDef.expiry.renewable !== 'boolean') {
          return { valid: false, reason: `class '${classId}' missing expiry config` };
        }
        if (typeof classDef.cascade_revoke !== 'boolean') {
          return { valid: false, reason: `class '${classId}' missing cascade_revoke` };
        }
        
        // Validate scope references exist
        for (const scopeClass of classDef.scope) {
          if (!schema.classes[scopeClass]) {
            return { valid: false, reason: `class '${classId}' scope references unknown class '${scopeClass}'` };
          }
        }
        
        // Validate issued_by references exist (except 'root')
        for (const issuer of classDef.issued_by) {
          if (issuer !== 'root' && !schema.classes[issuer]) {
            return { valid: false, reason: `class '${classId}' issued_by references unknown class '${issuer}'` };
          }
        }
      }
      
      return { valid: true };
    } catch {
      return { valid: false, reason: 'invalid JSON content' };
    }
  }
}
