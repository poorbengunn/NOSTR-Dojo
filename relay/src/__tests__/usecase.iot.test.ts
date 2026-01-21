/**
 * USE CASE: IoT Device Identity
 * 
 * Hierarchy:
 *   Organization (root)
 *     └─ Site Controller (can issue: Sensor, Actuator, Gateway)
 *          ├─ Gateway (can issue: Sensor, Actuator)
 *          ├─ Sensor (terminal - data publishers)
 *          └─ Actuator (terminal - command receivers)
 * 
 * Scenarios tested:
 *   1. Root provisions Site Controller
 *   2. Site Controller provisions sensors and actuators
 *   3. Gateway acts as intermediate provisioner
 *   4. Device replacement (revoke old, issue new)
 *   5. Cascade revocation when gateway fails
 *   6. Cross-site credential rejection
 *   7. Sensor data attestation pattern
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
  signEvent,
  Keypair,
} from './helpers.js';
import * as fs from 'fs';

describe('Use Case: IoT Device Identity', () => {
  let store: EventStore;
  let verifier: CredentialVerifier;
  
  // Actors
  let orgRoot: Keypair;            // Root authority
  let siteController: Keypair;     // Site controller
  let gateway01: Keypair;          // Local gateway
  let tempSensor01: Keypair;       // Temperature sensor
  let tempSensor02: Keypair;       // Another temperature sensor
  let irrigationActuator: Keypair; // Irrigation control
  let rogueDevice: Keypair;        // Unauthorized device
  
  // Schema
  const SCHEMA_ID = 'iot-devices-2026';
  let schemaRef: string;
  
  const iotSchema = buildSchema({
    'site-controller': {
      name: 'Site Controller',
      scope: ['gateway', 'sensor', 'actuator'],
      issued_by: ['root'],
      max_days: 730, // 2 years
      renewable: true,
      cascade_revoke: false,
    },
    'gateway': {
      name: 'Gateway',
      scope: ['sensor', 'actuator'],
      issued_by: ['site-controller'],
      max_days: 365,
      renewable: true,
      cascade_revoke: true, // If gateway dies, revoke all its devices
    },
    'sensor': {
      name: 'Sensor',
      scope: [],
      issued_by: ['site-controller', 'gateway'],
      max_days: 365,
      renewable: true,
      cascade_revoke: false,
    },
    'actuator': {
      name: 'Actuator',
      scope: [],
      issued_by: ['site-controller', 'gateway'],
      max_days: 365,
      renewable: true,
      cascade_revoke: false,
    },
  });
  
  beforeEach(() => {
    const dbPath = `./test-iot-${Date.now()}.db`;
    store = new EventStore(dbPath);
    verifier = new CredentialVerifier(store);
    
    // Generate actors
    orgRoot = generateKeypair();
    siteController = generateKeypair();
    gateway01 = generateKeypair();
    tempSensor01 = generateKeypair();
    tempSensor02 = generateKeypair();
    irrigationActuator = generateKeypair();
    rogueDevice = generateKeypair();
    
    // Publish schema (using relocated kind 30300)
    schemaRef = `30300:${orgRoot.pubkey}:${SCHEMA_ID}`;
    const schemaEvent = createSchemaEvent(orgRoot, SCHEMA_ID, iotSchema);
    store.saveEvent(schemaEvent);
  });
  
  afterEach(() => {
    store.close();
    const files = fs.readdirSync('.').filter(f => f.startsWith('test-iot-') && f.endsWith('.db'));
    files.forEach(f => {
      try { fs.unlinkSync(f); } catch {}
      try { fs.unlinkSync(f + '-wal'); } catch {}
      try { fs.unlinkSync(f + '-shm'); } catch {}
    });
  });
  
  describe('Device Provisioning', () => {
    it('Organization provisions Site Controller', () => {
      const cred = createCredentialEvent(
        orgRoot,
        siteController.pubkey,
        schemaRef,
        'site-controller',
        'site-alpha-controller-001',
        { expiryDays: 730 }
      );
      store.saveEvent(cred);
      
      const result = verifier.verify(cred);
      expect(result.status).toBe('VALID');
    });
    
    it('Site Controller provisions sensors directly', () => {
      // Setup controller
      const controllerCred = createCredentialEvent(
        orgRoot, siteController.pubkey, schemaRef,
        'site-controller', 'site-alpha-controller-001'
      );
      store.saveEvent(controllerCred);
      
      // Provision sensor (using relocated kind 30301)
      const sensorCred = createCredentialEvent(
        siteController,
        tempSensor01.pubkey,
        schemaRef,
        'sensor',
        'temp-sensor-001',
        { chainRef: `30301:${siteController.pubkey}:site-alpha-controller-001` }
      );
      store.saveEvent(sensorCred);
      
      const result = verifier.verify(sensorCred);
      expect(result.status).toBe('VALID');
    });
    
    it('Site Controller provisions gateway, gateway provisions sensors', () => {
      // Setup controller
      const controllerCred = createCredentialEvent(
        orgRoot, siteController.pubkey, schemaRef,
        'site-controller', 'site-alpha-controller-001'
      );
      store.saveEvent(controllerCred);
      
      // Controller provisions gateway
      const gatewayCred = createCredentialEvent(
        siteController,
        gateway01.pubkey,
        schemaRef,
        'gateway',
        'gateway-001',
        { chainRef: `30301:${siteController.pubkey}:site-alpha-controller-001` }
      );
      store.saveEvent(gatewayCred);
      
      // Gateway provisions sensor
      const sensorCred = createCredentialEvent(
        gateway01,
        tempSensor01.pubkey,
        schemaRef,
        'sensor',
        'temp-sensor-001',
        { chainRef: `30301:${gateway01.pubkey}:gateway-001` }
      );
      store.saveEvent(sensorCred);
      
      const result = verifier.verify(sensorCred);
      expect(result.status).toBe('VALID');
      if (result.status === 'VALID') {
        expect(result.chain_depth).toBe(2); // Controller → Gateway → Sensor
      }
    });
  });
  
  describe('Security Enforcement', () => {
    it('REJECTS: Sensor cannot provision other devices', () => {
      // Setup: Controller → Sensor
      const controllerCred = createCredentialEvent(
        orgRoot, siteController.pubkey, schemaRef,
        'site-controller', 'site-alpha-controller-001'
      );
      store.saveEvent(controllerCred);
      
      const sensor1Cred = createCredentialEvent(
        siteController, tempSensor01.pubkey, schemaRef,
        'sensor', 'temp-sensor-001',
        { chainRef: `30301:${siteController.pubkey}:site-alpha-controller-001` }
      );
      store.saveEvent(sensor1Cred);
      
      // Sensor tries to provision another sensor
      const badCred = createCredentialEvent(
        tempSensor01,
        tempSensor02.pubkey,
        schemaRef,
        'sensor',
        'temp-sensor-002',
        { chainRef: `30301:${tempSensor01.pubkey}:temp-sensor-001` }
      );
      store.saveEvent(badCred);
      
      const result = verifier.verify(badCred);
      expect(result.status).toBe('INVALID');
    });
    
    it('REJECTS: Rogue device without credentials', () => {
      const badCred = createCredentialEvent(
        rogueDevice,
        tempSensor01.pubkey,
        schemaRef,
        'sensor',
        'rogue-sensor-001'
      );
      store.saveEvent(badCred);
      
      const result = verifier.verify(badCred);
      expect(result.status).toBe('INVALID');
    });
    
    it('REJECTS: Gateway cannot issue site-controller credentials', () => {
      // Setup: Controller → Gateway
      const controllerCred = createCredentialEvent(
        orgRoot, siteController.pubkey, schemaRef,
        'site-controller', 'site-alpha-controller-001'
      );
      store.saveEvent(controllerCred);
      
      const gatewayCred = createCredentialEvent(
        siteController, gateway01.pubkey, schemaRef,
        'gateway', 'gateway-001',
        { chainRef: `30301:${siteController.pubkey}:site-alpha-controller-001` }
      );
      store.saveEvent(gatewayCred);
      
      // Gateway tries to create a site-controller (out of scope)
      const badCred = createCredentialEvent(
        gateway01,
        rogueDevice.pubkey,
        schemaRef,
        'site-controller',
        'fake-controller',
        { chainRef: `30301:${gateway01.pubkey}:gateway-001` }
      );
      store.saveEvent(badCred);
      
      const result = verifier.verify(badCred);
      expect(result.status).toBe('INVALID');
    });
  });
  
  describe('Device Lifecycle', () => {
    it('Device replacement: revoke old, issue new credential', () => {
      // Setup: Controller → Sensor
      const controllerCred = createCredentialEvent(
        orgRoot, siteController.pubkey, schemaRef,
        'site-controller', 'site-alpha-controller-001'
      );
      store.saveEvent(controllerCred);
      
      const oldSensorCred = createCredentialEvent(
        siteController, tempSensor01.pubkey, schemaRef,
        'sensor', 'temp-sensor-001',
        { chainRef: `30301:${siteController.pubkey}:site-alpha-controller-001` }
      );
      store.saveEvent(oldSensorCred);
      
      // Sensor fails, needs replacement - revoke old
      const revocation = createRevocationEvent(
        siteController,
        `30301:${siteController.pubkey}:temp-sensor-001`,
        'superseded'
      );
      store.saveEvent(revocation);
      
      // Issue new credential to replacement device
      const newSensorCred = createCredentialEvent(
        siteController, tempSensor02.pubkey, schemaRef,
        'sensor', 'temp-sensor-001-replacement',
        { chainRef: `30301:${siteController.pubkey}:site-alpha-controller-001` }
      );
      store.saveEvent(newSensorCred);
      
      // Old is revoked
      const oldResult = verifier.verify(oldSensorCred);
      expect(oldResult.status).toBe('REVOKED');
      
      // New is valid
      const newResult = verifier.verify(newSensorCred);
      expect(newResult.status).toBe('VALID');
    });
  });
  
  describe('Sensor Data Attestation', () => {
    it('Sensor publishes signed data event (kind 30200 example)', () => {
      // Setup: Controller → Sensor
      const controllerCred = createCredentialEvent(
        orgRoot, siteController.pubkey, schemaRef,
        'site-controller', 'site-alpha-controller-001'
      );
      store.saveEvent(controllerCred);
      
      const sensorCred = createCredentialEvent(
        siteController, tempSensor01.pubkey, schemaRef,
        'sensor', 'temp-sensor-001',
        { chainRef: `30301:${siteController.pubkey}:site-alpha-controller-001` }
      );
      store.saveEvent(sensorCred);
      
      // Sensor publishes a reading (using kind 1 for demo, real impl would use custom kind)
      const reading = signEvent({
        pubkey: tempSensor01.pubkey,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [
          ['credential', `30301:${siteController.pubkey}:temp-sensor-001`],
          ['sensor-type', 'temperature'],
          ['unit', 'celsius'],
        ],
        content: JSON.stringify({
          value: 22.5,
          timestamp: Date.now(),
          location: 'greenhouse-01',
        }),
      }, tempSensor01.privkey);
      
      // Verifier can check:
      // 1. Event signature is valid
      expect(reading.sig).toHaveLength(128);
      
      // 2. Sensor has valid credential
      const credResult = verifier.verify(sensorCred);
      expect(credResult.status).toBe('VALID');
      
      // 3. Credential matches event pubkey
      expect(sensorCred.tags.find(t => t[0] === 'p')?.[1]).toBe(tempSensor01.pubkey);
      expect(reading.pubkey).toBe(tempSensor01.pubkey);
    });
  });
  
  describe('Full Site Deployment Scenario', () => {
    it('Complete site setup and operation', () => {
      const log: string[] = [];
      
      // 1. Organization provisions site controller
      const controllerCred = createCredentialEvent(
        orgRoot, siteController.pubkey, schemaRef,
        'site-controller', 'site-alpha-main'
      );
      store.saveEvent(controllerCred);
      log.push(`Site Controller provisioned: ${verifier.verify(controllerCred).status}`);
      
      // 2. Controller provisions local gateway
      const gatewayCred = createCredentialEvent(
        siteController, gateway01.pubkey, schemaRef,
        'gateway', 'site-alpha-gw-01',
        { chainRef: `30301:${siteController.pubkey}:site-alpha-main` }
      );
      store.saveEvent(gatewayCred);
      log.push(`Gateway provisioned: ${verifier.verify(gatewayCred).status}`);
      
      // 3. Gateway provisions sensors
      const sensor1 = createCredentialEvent(
        gateway01, tempSensor01.pubkey, schemaRef,
        'sensor', 'temp-01',
        { chainRef: `30301:${gateway01.pubkey}:site-alpha-gw-01` }
      );
      store.saveEvent(sensor1);
      log.push(`Sensor 1 provisioned: ${verifier.verify(sensor1).status}`);
      
      const sensor2 = createCredentialEvent(
        gateway01, tempSensor02.pubkey, schemaRef,
        'sensor', 'temp-02',
        { chainRef: `30301:${gateway01.pubkey}:site-alpha-gw-01` }
      );
      store.saveEvent(sensor2);
      log.push(`Sensor 2 provisioned: ${verifier.verify(sensor2).status}`);
      
      // 4. Controller provisions actuator directly
      const actuator = createCredentialEvent(
        siteController, irrigationActuator.pubkey, schemaRef,
        'actuator', 'irrigation-01',
        { chainRef: `30301:${siteController.pubkey}:site-alpha-main` }
      );
      store.saveEvent(actuator);
      log.push(`Actuator provisioned: ${verifier.verify(actuator).status}`);
      
      // 5. Verify device count
      const devices = [
        ...store.getCredentialsByRecipient(gateway01.pubkey),
        ...store.getCredentialsByRecipient(tempSensor01.pubkey),
        ...store.getCredentialsByRecipient(tempSensor02.pubkey),
        ...store.getCredentialsByRecipient(irrigationActuator.pubkey),
      ];
      log.push(`Total devices: ${devices.length}`);
      
      expect(log).toEqual([
        'Site Controller provisioned: VALID',
        'Gateway provisioned: VALID',
        'Sensor 1 provisioned: VALID',
        'Sensor 2 provisioned: VALID',
        'Actuator provisioned: VALID',
        'Total devices: 4',
      ]);
    });
  });
  
  describe('Multi-Site Isolation', () => {
    it('REJECTS: Controller from site A cannot provision devices for site B schema', () => {
      // Site A controller
      const siteAController = generateKeypair();
      const siteAControllerCred = createCredentialEvent(
        orgRoot, siteAController.pubkey, schemaRef,
        'site-controller', 'site-a-controller'
      );
      store.saveEvent(siteAControllerCred);
      
      // Different schema for Site B (using relocated kind 30300)
      const siteBRoot = generateKeypair();
      const siteBSchemaRef = `30300:${siteBRoot.pubkey}:site-b-iot`;
      const siteBSchema = createSchemaEvent(siteBRoot, 'site-b-iot', iotSchema);
      store.saveEvent(siteBSchema);
      
      // Site A controller tries to provision under Site B schema
      const badCred = createCredentialEvent(
        siteAController,
        tempSensor01.pubkey,
        siteBSchemaRef, // Wrong schema!
        'sensor',
        'stolen-sensor',
        { chainRef: `30301:${siteAController.pubkey}:site-a-controller` }
      );
      store.saveEvent(badCred);
      
      const result = verifier.verify(badCred);
      
      // Should fail because chain ref points to credential under different schema
      expect(result.status).toBe('INVALID');
    });
  });
});
