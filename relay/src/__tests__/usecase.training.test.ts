/**
 * USE CASE: Training Credentials (The Dojo / Lyceum)
 * 
 * Hierarchy:
 *   Citadel (root)
 *     └─ Course Director (can issue: Instructor)
 *          └─ Instructor (can issue: Trainee)
 *               └─ Trainee (terminal)
 * 
 * Scenarios tested:
 *   1. Root issues Course Director credential
 *   2. Course Director issues Instructor credential
 *   3. Instructor issues Trainee credential
 *   4. Full chain verification
 *   5. Expired credential rejection
 *   6. Revocation propagation
 *   7. Unauthorized issuance rejection
 *   8. Credential renewal
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { EventStore } from '../database.js';
import { CredentialVerifier } from '../credentials.js';
import {
  generateKeypair,
  buildSchema,
  createSchemaEvent,
  createCredentialEvent,
  createRevocationEvent,
  createRenewalEvent,
  daysAgo,
  daysFromNow,
  Keypair,
} from './helpers.js';
import * as fs from 'fs';

describe('Use Case: Training Credentials (The Dojo)', () => {
  let store: EventStore;
  let verifier: CredentialVerifier;
  
  // Actors
  let citadel: Keypair;      // Root authority
  let sean: Keypair;         // Course Director (Director of Praxis)
  let alice: Keypair;        // Instructor
  let bob: Keypair;          // Trainee
  let mallory: Keypair;      // Unauthorized actor
  
  // Schema
  const SCHEMA_ID = 'dojo-training-2026';
  let schemaRef: string;
  
  const trainingSchema = buildSchema({
    'course-director': {
      name: 'Course Director',
      scope: ['instructor'],
      issued_by: ['root'],
      max_days: 365,
      renewable: true,
      cascade_revoke: false,
    },
    'instructor': {
      name: 'Instructor',
      scope: ['trainee'],
      issued_by: ['course-director'],
      max_days: 365,
      renewable: true,
      cascade_revoke: false,
    },
    'trainee': {
      name: 'Trainee',
      scope: [],
      issued_by: ['instructor'],
      max_days: 180,
      renewable: false,
      cascade_revoke: false,
    },
  });
  
  beforeEach(() => {
    // Fresh database for each test
    const dbPath = `./test-dojo-${Date.now()}.db`;
    store = new EventStore(dbPath);
    verifier = new CredentialVerifier(store);
    
    // Generate actors
    citadel = generateKeypair();
    sean = generateKeypair();
    alice = generateKeypair();
    bob = generateKeypair();
    mallory = generateKeypair();
    
    // Publish schema
    schemaRef = `30100:${citadel.pubkey}:${SCHEMA_ID}`;
    const schemaEvent = createSchemaEvent(citadel, SCHEMA_ID, trainingSchema);
    store.saveEvent(schemaEvent);
  });
  
  afterEach(() => {
    store.close();
    // Cleanup test databases
    const files = fs.readdirSync('.').filter(f => f.startsWith('test-dojo-') && f.endsWith('.db'));
    files.forEach(f => {
      try { fs.unlinkSync(f); } catch {}
      try { fs.unlinkSync(f + '-wal'); } catch {}
      try { fs.unlinkSync(f + '-shm'); } catch {}
    });
  });
  
  describe('Happy Path: Full Chain Issuance', () => {
    it('Citadel issues Course Director credential to Sean', () => {
      const cred = createCredentialEvent(
        citadel,
        sean.pubkey,
        schemaRef,
        'course-director',
        'sean-director-2026',
        { expiryDays: 365 }
      );
      
      store.saveEvent(cred);
      const result = verifier.verify(cred);
      
      expect(result.status).toBe('VALID');
      if (result.status === 'VALID') {
        expect(result.chain_depth).toBe(0); // Direct from root
      }
    });
    
    it('Sean (Course Director) issues Instructor credential to Alice', () => {
      // First: Sean needs his Course Director credential
      const seanCred = createCredentialEvent(
        citadel,
        sean.pubkey,
        schemaRef,
        'course-director',
        'sean-director-2026',
        { expiryDays: 365 }
      );
      store.saveEvent(seanCred);
      
      // Now Sean can issue to Alice
      const aliceCred = createCredentialEvent(
        sean,
        alice.pubkey,
        schemaRef,
        'instructor',
        'alice-instructor-2026',
        {
          expiryDays: 365,
          chainRef: `30101:${sean.pubkey}:sean-director-2026`,
        }
      );
      store.saveEvent(aliceCred);
      
      const result = verifier.verify(aliceCred);
      
      expect(result.status).toBe('VALID');
      if (result.status === 'VALID') {
        expect(result.chain_depth).toBe(1); // One hop from root
      }
    });
    
    it('Alice (Instructor) issues Trainee credential to Bob', () => {
      // Setup chain: Citadel → Sean → Alice
      const seanCred = createCredentialEvent(
        citadel, sean.pubkey, schemaRef, 'course-director', 'sean-director-2026'
      );
      store.saveEvent(seanCred);
      
      const aliceCred = createCredentialEvent(
        sean, alice.pubkey, schemaRef, 'instructor', 'alice-instructor-2026',
        { chainRef: `30101:${sean.pubkey}:sean-director-2026` }
      );
      store.saveEvent(aliceCred);
      
      // Now Alice issues to Bob
      const bobCred = createCredentialEvent(
        alice,
        bob.pubkey,
        schemaRef,
        'trainee',
        'bob-trainee-2026',
        {
          expiryDays: 180,
          chainRef: `30101:${alice.pubkey}:alice-instructor-2026`,
        }
      );
      store.saveEvent(bobCred);
      
      const result = verifier.verify(bobCred);
      
      expect(result.status).toBe('VALID');
      if (result.status === 'VALID') {
        expect(result.chain_depth).toBe(2); // Two hops from root
      }
    });
  });
  
  describe('Authorization Enforcement', () => {
    it('REJECTS: Trainee cannot issue credentials (no scope)', () => {
      // Setup full chain to Bob
      const seanCred = createCredentialEvent(
        citadel, sean.pubkey, schemaRef, 'course-director', 'sean-director-2026'
      );
      store.saveEvent(seanCred);
      
      const aliceCred = createCredentialEvent(
        sean, alice.pubkey, schemaRef, 'instructor', 'alice-instructor-2026',
        { chainRef: `30101:${sean.pubkey}:sean-director-2026` }
      );
      store.saveEvent(aliceCred);
      
      const bobCred = createCredentialEvent(
        alice, bob.pubkey, schemaRef, 'trainee', 'bob-trainee-2026',
        { chainRef: `30101:${alice.pubkey}:alice-instructor-2026` }
      );
      store.saveEvent(bobCred);
      
      // Bob tries to issue a trainee credential to mallory
      const malloryCred = createCredentialEvent(
        bob,
        mallory.pubkey,
        schemaRef,
        'trainee',
        'mallory-trainee-2026',
        { chainRef: `30101:${bob.pubkey}:bob-trainee-2026` }
      );
      store.saveEvent(malloryCred);
      
      const result = verifier.verify(malloryCred);
      
      expect(result.status).toBe('INVALID');
      if (result.status === 'INVALID') {
        expect(result.reason).toContain('scope');
      }
    });
    
    it('REJECTS: Instructor cannot issue Course Director (out of scope)', () => {
      // Setup: Sean → Alice
      const seanCred = createCredentialEvent(
        citadel, sean.pubkey, schemaRef, 'course-director', 'sean-director-2026'
      );
      store.saveEvent(seanCred);
      
      const aliceCred = createCredentialEvent(
        sean, alice.pubkey, schemaRef, 'instructor', 'alice-instructor-2026',
        { chainRef: `30101:${sean.pubkey}:sean-director-2026` }
      );
      store.saveEvent(aliceCred);
      
      // Alice tries to issue a Course Director credential
      const badCred = createCredentialEvent(
        alice,
        bob.pubkey,
        schemaRef,
        'course-director',
        'bob-fake-director',
        { chainRef: `30101:${alice.pubkey}:alice-instructor-2026` }
      );
      store.saveEvent(badCred);
      
      const result = verifier.verify(badCred);
      
      expect(result.status).toBe('INVALID');
    });
    
    it('REJECTS: Random person cannot issue credentials', () => {
      // Mallory tries to issue without any credentials
      const badCred = createCredentialEvent(
        mallory,
        bob.pubkey,
        schemaRef,
        'instructor',
        'bob-fake-instructor'
        // No chainRef - claiming to be root
      );
      store.saveEvent(badCred);
      
      const result = verifier.verify(badCred);
      
      expect(result.status).toBe('INVALID');
    });
  });
  
  describe('Expiry Handling', () => {
    it('REJECTS: Expired credential', () => {
      const expiredCred = createCredentialEvent(
        citadel,
        sean.pubkey,
        schemaRef,
        'course-director',
        'sean-expired',
        {
          expiryDays: -30, // Expired 30 days ago
          timestamp: daysAgo(60), // Issued 60 days ago
        }
      );
      store.saveEvent(expiredCred);
      
      const result = verifier.verify(expiredCred);
      
      expect(result.status).toBe('EXPIRED');
    });
    
    it('ACCEPTS: Renewed credential extends validity', () => {
      // Issue credential that would be expired
      const now = Math.floor(Date.now() / 1000);
      const cred = createCredentialEvent(
        citadel,
        sean.pubkey,
        schemaRef,
        'course-director',
        'sean-renewed',
        {
          expiryDays: 30,
          timestamp: daysAgo(60), // Issued 60 days ago, expired 30 days ago
        }
      );
      store.saveEvent(cred);
      
      // Renew it
      const renewal = createRenewalEvent(
        citadel,
        `30101:${citadel.pubkey}:sean-renewed`,
        365, // New expiry: 365 days from now
        now
      );
      store.saveEvent(renewal);
      
      const result = verifier.verify(cred);
      
      expect(result.status).toBe('VALID');
    });
    
    it('REJECTS: Issuer credential expired at time of issuance', () => {
      // Sean's credential expired before he issued to Alice
      const seanCred = createCredentialEvent(
        citadel,
        sean.pubkey,
        schemaRef,
        'course-director',
        'sean-short-lived',
        {
          expiryDays: 30,
          timestamp: daysAgo(60), // Issued 60 days ago, expired 30 days ago
        }
      );
      store.saveEvent(seanCred);
      
      // Sean tries to issue after his credential expired
      const aliceCred = createCredentialEvent(
        sean,
        alice.pubkey,
        schemaRef,
        'instructor',
        'alice-invalid',
        {
          chainRef: `30101:${sean.pubkey}:sean-short-lived`,
          timestamp: daysAgo(10), // Issued 10 days ago (after Sean's expired)
        }
      );
      store.saveEvent(aliceCred);
      
      const result = verifier.verify(aliceCred);
      
      expect(result.status).toBe('INVALID');
      if (result.status === 'INVALID') {
        expect(result.reason).toContain('expired at issuance');
      }
    });
  });
  
  describe('Revocation', () => {
    it('REJECTS: Revoked credential', () => {
      const cred = createCredentialEvent(
        citadel,
        sean.pubkey,
        schemaRef,
        'course-director',
        'sean-revoked'
      );
      store.saveEvent(cred);
      
      // Revoke it
      const revocation = createRevocationEvent(
        citadel,
        `30101:${citadel.pubkey}:sean-revoked`,
        'misconduct'
      );
      store.saveEvent(revocation);
      
      const result = verifier.verify(cred);
      
      expect(result.status).toBe('REVOKED');
      if (result.status === 'REVOKED') {
        expect(result.reason).toBe('misconduct');
      }
    });
    
    it('Root can revoke any credential in chain', () => {
      // Full chain
      const seanCred = createCredentialEvent(
        citadel, sean.pubkey, schemaRef, 'course-director', 'sean-director-2026'
      );
      store.saveEvent(seanCred);
      
      const aliceCred = createCredentialEvent(
        sean, alice.pubkey, schemaRef, 'instructor', 'alice-instructor-2026',
        { chainRef: `30101:${sean.pubkey}:sean-director-2026` }
      );
      store.saveEvent(aliceCred);
      
      // Root revokes Alice's credential directly
      const revocation = createRevocationEvent(
        citadel,
        `30101:${sean.pubkey}:alice-instructor-2026`,
        'fraud'
      );
      store.saveEvent(revocation);
      
      const result = verifier.verify(aliceCred);
      
      expect(result.status).toBe('REVOKED');
    });
  });
  
  describe('Real-World Scenario: Course Lifecycle', () => {
    it('Complete course certification flow', () => {
      const results: string[] = [];
      
      // 1. Citadel appoints Sean as Course Director
      const seanDirector = createCredentialEvent(
        citadel, sean.pubkey, schemaRef, 'course-director', 'sean-cd-001'
      );
      store.saveEvent(seanDirector);
      results.push(`Sean appointed as Course Director: ${verifier.verify(seanDirector).status}`);
      
      // 2. Sean certifies Alice as Instructor
      const aliceInstructor = createCredentialEvent(
        sean, alice.pubkey, schemaRef, 'instructor', 'alice-inst-001',
        { chainRef: `30101:${sean.pubkey}:sean-cd-001` }
      );
      store.saveEvent(aliceInstructor);
      results.push(`Alice certified as Instructor: ${verifier.verify(aliceInstructor).status}`);
      
      // 3. Alice certifies Bob as Trainee (completes course)
      const bobTrainee = createCredentialEvent(
        alice, bob.pubkey, schemaRef, 'trainee', 'bob-trainee-001',
        { chainRef: `30101:${alice.pubkey}:alice-inst-001`, expiryDays: 180 }
      );
      store.saveEvent(bobTrainee);
      results.push(`Bob certified as Trainee: ${verifier.verify(bobTrainee).status}`);
      
      // 4. Query Bob's credentials
      const bobCreds = store.getCredentialsByRecipient(bob.pubkey);
      results.push(`Bob has ${bobCreds.length} credential(s)`);
      
      // All should be valid
      expect(results).toEqual([
        'Sean appointed as Course Director: VALID',
        'Alice certified as Instructor: VALID',
        'Bob certified as Trainee: VALID',
        'Bob has 1 credential(s)',
      ]);
    });
  });
});
