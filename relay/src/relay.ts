import { WebSocketServer, WebSocket } from 'ws';
import type { NostrEvent, Filter, ClientMessage, RelayMessage } from './types.js';
import { EVENT_KINDS } from './types.js';
import { validateEvent } from './crypto.js';
import { EventStore } from './database.js';
import { CredentialVerifier } from './credentials.js';

interface Subscription {
  id: string;
  filters: Filter[];
}

interface Client {
  ws: WebSocket;
  subscriptions: Map<string, Subscription>;
}

export class DojoRelay {
  private wss: WebSocketServer;
  private store: EventStore;
  private verifier: CredentialVerifier;
  private clients: Set<Client> = new Set();
  
  constructor(port: number = 8080, dbPath: string = './dojo-relay.db') {
    this.store = new EventStore(dbPath);
    this.verifier = new CredentialVerifier(this.store);
    
    this.wss = new WebSocketServer({ port });
    
    this.wss.on('connection', (ws) => this.handleConnection(ws));
    this.wss.on('error', (err) => console.error('[Relay] Server error:', err));
    
    console.log(`[Relay] Dojo Relay started on ws://localhost:${port}`);
    console.log('[Relay] Supported NIPs: 1, 9, 11, 16, 20, 33, 58, XXX (Hierarchical Credentials)');
  }
  
  private handleConnection(ws: WebSocket): void {
    const client: Client = {
      ws,
      subscriptions: new Map(),
    };
    
    this.clients.add(client);
    console.log(`[Relay] Client connected. Total: ${this.clients.size}`);
    
    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString()) as ClientMessage;
        this.handleMessage(client, message);
      } catch (err) {
        this.send(client, ['NOTICE', 'Invalid JSON']);
      }
    });
    
    ws.on('close', () => {
      this.clients.delete(client);
      console.log(`[Relay] Client disconnected. Total: ${this.clients.size}`);
    });
    
    ws.on('error', (err) => {
      console.error('[Relay] Client error:', err);
    });
  }
  
  private handleMessage(client: Client, message: ClientMessage): void {
    const [type] = message;
    
    switch (type) {
      case 'EVENT':
        this.handleEvent(client, message[1]);
        break;
      case 'REQ':
        this.handleReq(client, message[1], message.slice(2) as Filter[]);
        break;
      case 'CLOSE':
        this.handleClose(client, message[1]);
        break;
      default:
        this.send(client, ['NOTICE', `Unknown message type: ${type}`]);
    }
  }
  
  private handleEvent(client: Client, event: NostrEvent): void {
    // Validate event structure and signature
    const validation = validateEvent(event);
    if (!validation.valid) {
      this.send(client, ['OK', event.id, false, `invalid: ${validation.reason}`]);
      return;
    }
    
    // Additional validation for credential events
    if (event.kind === EVENT_KINDS.CREDENTIAL_SCHEMA) {
      const schemaValidation = this.verifier.validateSchema(event);
      if (!schemaValidation.valid) {
        this.send(client, ['OK', event.id, false, `invalid: ${schemaValidation.reason}`]);
        return;
      }
    }
    
    if (event.kind === EVENT_KINDS.CREDENTIAL_GRANT) {
      const credValidation = this.verifier.validateCredentialGrant(event);
      if (!credValidation.valid) {
        this.send(client, ['OK', event.id, false, `invalid: ${credValidation.reason}`]);
        return;
      }
      
      // Verify issuer has authority
      // Note: Schema must be stored first for this to work
      const verifyResult = this.verifier.verify(event);
      if (verifyResult.status !== 'VALID') {
        this.send(client, ['OK', event.id, false, `invalid: credential verification failed - ${verifyResult.status}`]);
        return;
      }
    }
    
    // Handle deletion (NIP-09)
    if (event.kind === 5) {
      const eTags = event.tags.filter(t => t[0] === 'e');
      for (const tag of eTags) {
        if (tag[1]) {
          this.store.deleteEvent(tag[1], event.pubkey);
        }
      }
    }
    
    // Store event
    const saved = this.store.saveEvent(event);
    
    if (saved) {
      this.send(client, ['OK', event.id, true, '']);
      
      // Broadcast to subscribers
      this.broadcast(event);
    } else {
      this.send(client, ['OK', event.id, false, 'error: could not save event']);
    }
  }
  
  private handleReq(client: Client, subId: string, filters: Filter[]): void {
    // Store subscription
    client.subscriptions.set(subId, { id: subId, filters });
    
    // Query stored events
    const events = new Set<string>();
    
    for (const filter of filters) {
      const results = this.store.queryEvents(filter);
      for (const event of results) {
        if (!events.has(event.id)) {
          events.add(event.id);
          this.send(client, ['EVENT', subId, event]);
        }
      }
    }
    
    // Send EOSE
    this.send(client, ['EOSE', subId]);
  }
  
  private handleClose(client: Client, subId: string): void {
    client.subscriptions.delete(subId);
    this.send(client, ['CLOSED', subId, '']);
  }
  
  private broadcast(event: NostrEvent): void {
    for (const client of this.clients) {
      for (const sub of client.subscriptions.values()) {
        if (this.matchesFilters(event, sub.filters)) {
          this.send(client, ['EVENT', sub.id, event]);
          break; // Only send once per subscription
        }
      }
    }
  }
  
  private matchesFilters(event: NostrEvent, filters: Filter[]): boolean {
    return filters.some(filter => this.matchesFilter(event, filter));
  }
  
  private matchesFilter(event: NostrEvent, filter: Filter): boolean {
    if (filter.ids?.length && !filter.ids.includes(event.id)) {
      return false;
    }
    
    if (filter.authors?.length && !filter.authors.includes(event.pubkey)) {
      return false;
    }
    
    if (filter.kinds?.length && !filter.kinds.includes(event.kind)) {
      return false;
    }
    
    if (filter.since !== undefined && event.created_at < filter.since) {
      return false;
    }
    
    if (filter.until !== undefined && event.created_at > filter.until) {
      return false;
    }
    
    // Tag filters
    if (filter['#e']?.length) {
      const eventRefs = event.tags.filter(t => t[0] === 'e').map(t => t[1]);
      if (!filter['#e'].some(e => eventRefs.includes(e))) {
        return false;
      }
    }
    
    if (filter['#p']?.length) {
      const pubkeyRefs = event.tags.filter(t => t[0] === 'p').map(t => t[1]);
      if (!filter['#p'].some(p => pubkeyRefs.includes(p))) {
        return false;
      }
    }
    
    if (filter['#a']?.length) {
      const aTag = event.tags.find(t => t[0] === 'a')?.[1];
      if (!aTag || !filter['#a'].includes(aTag)) {
        return false;
      }
    }
    
    if (filter['#d']?.length) {
      const dTag = event.tags.find(t => t[0] === 'd')?.[1];
      if (!dTag || !filter['#d'].includes(dTag)) {
        return false;
      }
    }
    
    return true;
  }
  
  private send(client: Client, message: RelayMessage): void {
    if (client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(JSON.stringify(message));
    }
  }
  
  /**
   * Get relay info (NIP-11)
   */
  getInfo(): object {
    return {
      name: 'Dojo Relay',
      description: 'NOSTR relay with NIP-XXX Hierarchical Delegated Credentials support',
      pubkey: '', // Set your relay operator pubkey
      contact: '', // Set contact info
      supported_nips: [1, 9, 11, 16, 20, 33, 58],
      software: 'https://github.com/poorbengunn/NOSTR-Dojo',
      version: '0.1.0',
      limitation: {
        max_message_length: 65536,
        max_subscriptions: 20,
        max_filters: 10,
        max_event_tags: 100,
        max_content_length: 65536,
      },
    };
  }
  
  close(): void {
    this.wss.close();
    this.store.close();
  }
}
