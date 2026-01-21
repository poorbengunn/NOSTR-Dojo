/**
 * USE CASE: Training Credentials
 * 
 * Hierarchy:
 *   Organization (root)
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

describe('Use Case: Training Credentials', () => {
  let store: EventStore;
  let verifier: CredentialVerifier;
  
  // Actors
  let orgRoot: Keypair;      // Root authority
  let director: Keypair;     // Course Director
  let alice: Keypair;        // Instructor
  let bob: Keypair;          // Trainee
  let mallory: Keypair;      // Unauthorized actor
  
  // Schema
  const SCHEMA_ID = 'training-creds-2026';
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
    const dbPath = `./test-training-${Date.now()}.db`;
    store = new EventStore(dbPath);
    verifier = new CredentialVerifier(store);
    
    // Generate actors
    orgRoot = generateKeypair();
    director = generateKeypair();
    alice = generateKeypair();
    bob = generateKeypair();
    mallory = generateKeypair();
    
    // Publish schema (using relocated kind 30300)
    schemaRef = `30300:${orgRoot.pubkey}:${SCHEMA_ID}`;
    const schemaEvent = createSchemaEvent(orgRoot, SCHEMA_ID, trainingSchema);
    store.saveEvent(schemaEvent);
  });
  
  afterEach(() => {
    store.close();
    // Cleanup test databases
    const files = fs.readdirSync('.').filter(f => f.startsWith('test-training-') && f.endsWith('.db'));
    files.forEach(f => {
      try { fs.unlinkSync(f); } catch {}
      try { fs.unlinkSync(f + '-wal'); } catch {}
      try { fs.unlinkSync(f + '-shm'); } catch {}
    });
  });
  
  describe('Happy Path: Full Chain Issuance', () => {
    it('Organization issues Course Director credential', () => {
      const cred = createCredentialEvent(
        orgRoot,
        director.pubkey,
        schemaRef,
        'course-director',
        'director-2026',
        { expiryDays: 365 }
      );
      
      store.saveEvent(cred);
      const result = verifier.verify(cred);
      
      expect(result.status).toBe('VALID');
      if (result.status === 'VALID') {
        expect(result.chain_depth).toBe(0); // Direct from root
      }
    });
    
    it('Course Director issues Instructor credential to Alice', () => {
      // First: Director needs their Course Director credential
      const directorCred = createCredentialEvent(
        orgRoot,
        director.pubkey,
        schemaRef,
        'course-director',
        'director-2026',
        { expiryDays: 365 }
      );
      store.saveEvent(directorCred);
      
      // Now Director can issue to Alice (using relocated kind 30301)
      const aliceCred = createCredentialEvent(
        director,
        alice.pubkey,
        schemaRef,
        'instructor',
        'alice-instructor-2026',
        {
          expiryDays: 365,
          chainRef: `30301:${director.pubkey}:director-2026`,
        }
      );
      store.saveEvent(aliceCred);
      
      const result = verifier.verify(aliceCred);
      
      expect(result.status).toBe('VALID');
      if (result.status === 'VALID') {
        expect(result.chain_depth).toBe(1); // One hop from root
      }
    });
    
    it('Instructor issues Trainee credential to Bob', () => {
      // Setup chain: Root → Director → Alice
      const directorCred = createCredentialEvent(
        orgRoot, director.pubkey, schemaRef, 'course-director', 'director-2026'
      );
      store.saveEvent(directorCred);
      
      const aliceCred = createCredentialEvent(
        director, alice.pubkey, schemaRef, 'instructor', 'alice-instructor-2026',
        { chainRef: `30301:${director.pubkey}:director-2026` }
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
          chainRef: `30301:${alice.pubkey}:alice-instructor-2026`,
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
      const directorCred = createCredentialEvent(
        orgRoot, director.pubkey, schemaRef, 'course-director', 'director-2026'
      );
      store.saveEvent(directorCred);
      
      const aliceCred = createCredentialEvent(
        director, alice.pubkey, schemaRef, 'instructor', 'alice-instructor-2026',
        { chainRef: `30301:${director.pubkey}:director-2026` }
      );
      store.saveEvent(aliceCred);
      
      const bobCred = createCredentialEvent(
        alice, bob.pubkey, schemaRef, 'trainee', 'bob-trainee-2026',
        { chainRef: `30301:${alice.pubkey}:alice-instructor-2026` }
      );
      store.saveEvent(bobCred);
      
      // Bob tries to issue a trainee credential to mallory
      const malloryCred = createCredentialEvent(
        bob,
        mallory.pubkey,
        schemaRef,
        'trainee',
        'mallory-trainee-2026',
        { chainRef: `30301:${bob.pubkey}:bob-trainee-2026` }
      );
      store.saveEvent(malloryCred);
      
      const result = verifier.verify(malloryCred);
      
      expect(result.status).toBe('INVALID');
      if (result.status === 'INVALID') {
        expect(result.reason).toContain('scope');
      }
    });
    
    it('REJECTS: Instructor cannot issue Course Director (out of scope)', () => {
      // Setup: Director → Alice
      const directorCred = createCredentialEvent(
        orgRoot, director.pubkey, schemaRef, 'course-director', 'director-2026'
      );
      store.saveEvent(directorCred);
      
      const aliceCred = createCredentialEvent(
        director, alice.pubkey, schemaRef, 'instructor', 'alice-instructor-2026',
        { chainRef: `30301:${director.pubkey}:director-2026` }
      );
      store.saveEvent(aliceCred);
      
      // Alice tries to issue a Course Director credential
      const badCred = createCredentialEvent(
        alice,
        bob.pubkey,
        schemaRef,
        'course-director',
        'bob-fake-director',
        { chainRef: `30301:${alice.pubkey}:alice-instructor-2026` }
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
        orgRoot,
        director.pubkey,
        schemaRef,
        'course-director',
        'director-expired',
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
        orgRoot,
        director.pubkey,
        schemaRef,
        'course-director',
        'director-renewed',
        {
          expiryDays: 30,
          timestamp: daysAgo(60), // Issued 60 days ago, expired 30 days ago
        }
      );
      store.saveEvent(cred);
      
      // Renew it (using relocated kind 30301 in reference)
      const renewal = createRenewalEvent(
        orgRoot,
        `30301:${orgRoot.pubkey}:director-renewed`,
        365, // New expiry: 365 days from now
        now
      );
      store.saveEvent(renewal);
      
      const result = verifier.verify(cred);
      
      expect(result.status).toBe('VALID');
    });
    
    it('REJECTS: Issuer credential expired at time of issuance', () => {
      // Director's credential expired before they issued to Alice
      const directorCred = createCredentialEvent(
        orgRoot,
        director.pubkey,
        schemaRef,
        'course-director',
        'director-short-lived',
        {
          expiryDays: 30,
          timestamp: daysAgo(60), // Issued 60 days ago, expired 30 days ago
        }
      );
      store.saveEvent(directorCred);
      
      // Director tries to issue after their credential expired
      const aliceCred = createCredentialEvent(
        director,
        alice.pubkey,
        schemaRef,
        'instructor',
        'alice-invalid',
        {
          chainRef: `30301:${director.pubkey}:director-short-lived`,
          timestamp: daysAgo(10), // Issued 10 days ago (after Director's expired)
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
        orgRoot,
        director.pubkey,
        schemaRef,
        'course-director',
        'director-revoked'
      );
      store.saveEvent(cred);
      
      // Revoke it (using relocated kind 30301 in reference)
      const revocation = createRevocationEvent(
        orgRoot,
        `30301:${orgRoot.pubkey}:director-revoked`,
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
      const directorCred = createCredentialEvent(
        orgRoot, director.pubkey, schemaRef, 'course-director', 'director-2026'
      );
      store.saveEvent(directorCred);
      
      const aliceCred = createCredentialEvent(
        director, alice.pubkey, schemaRef, 'instructor', 'alice-instructor-2026',
        { chainRef: `30301:${director.pubkey}:director-2026` }
      );
      store.saveEvent(aliceCred);
      
      // Root revokes Alice's credential directly
      const revocation = createRevocationEvent(
        orgRoot,
        `30301:${director.pubkey}:alice-instructor-2026`,
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
      
      // 1. Organization appoints Director
      const directorCred = createCredentialEvent(
        orgRoot, director.pubkey, schemaRef, 'course-director', 'director-001'
      );
      store.saveEvent(directorCred);
      results.push(`Director appointed: ${verifier.verify(directorCred).status}`);
      
      // 2. Director certifies Alice as Instructor
      const aliceInstructor = createCredentialEvent(
        director, alice.pubkey, schemaRef, 'instructor', 'alice-inst-001',
        { chainRef: `30301:${director.pubkey}:director-001` }
      );
      store.saveEvent(aliceInstructor);
      results.push(`Alice certified as Instructor: ${verifier.verify(aliceInstructor).status}`);
      
      // 3. Alice certifies Bob as Trainee (completes course)
      const bobTrainee = createCredentialEvent(
        alice, bob.pubkey, schemaRef, 'trainee', 'bob-trainee-001',
        { chainRef: `30301:${alice.pubkey}:alice-inst-001`, expiryDays: 180 }
      );
      store.saveEvent(bobTrainee);
      results.push(`Bob certified as Trainee: ${verifier.verify(bobTrainee).status}`);
      
      // 4. Query Bob's credentials
      const bobCreds = store.getCredentialsByRecipient(bob.pubkey);
      results.push(`Bob has ${bobCreds.length} credential(s)`);
      
      // All should be valid
      expect(results).toEqual([
        'Director appointed: VALID',
        'Alice certified as Instructor: VALID',
        'Bob certified as Trainee: VALID',
        'Bob has 1 credential(s)',
      ]);
    });
  });
});
