import Database from 'better-sqlite3';
import type { NostrEvent, Filter, EventRow, CredentialRow } from './types.js';
import { EVENT_KINDS } from './types.js';
import { getTagValue } from './crypto.js';

export class EventStore {
  private db: Database.Database;
  
  constructor(dbPath: string = './dojo-relay.db') {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.init();
  }
  
  private init(): void {
    // Events table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        pubkey TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        kind INTEGER NOT NULL,
        tags TEXT NOT NULL,
        content TEXT NOT NULL,
        sig TEXT NOT NULL,
        d_tag TEXT,
        a_tag TEXT,
        expires_at INTEGER
      );
      
      CREATE INDEX IF NOT EXISTS idx_events_pubkey ON events(pubkey);
      CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
      CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
      CREATE INDEX IF NOT EXISTS idx_events_kind_pubkey_d ON events(kind, pubkey, d_tag);
    `);
    
    // Credential index for fast chain lookups
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS credentials (
        event_id TEXT PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
        schema_ref TEXT NOT NULL,
        class_id TEXT NOT NULL,
        recipient TEXT NOT NULL,
        issuer TEXT NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER,
        chain_ref TEXT,
        revoked INTEGER DEFAULT 0,
        revoked_at INTEGER,
        revoke_reason TEXT
      );
      
      CREATE INDEX IF NOT EXISTS idx_cred_recipient ON credentials(recipient);
      CREATE INDEX IF NOT EXISTS idx_cred_issuer ON credentials(issuer);
      CREATE INDEX IF NOT EXISTS idx_cred_schema ON credentials(schema_ref);
      CREATE INDEX IF NOT EXISTS idx_cred_class ON credentials(class_id);
      CREATE INDEX IF NOT EXISTS idx_cred_chain ON credentials(chain_ref);
    `);
    
    // Schemas cache
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schemas (
        ref TEXT PRIMARY KEY,
        pubkey TEXT NOT NULL,
        d_tag TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);
  }
  
  /**
   * Store an event
   */
  saveEvent(event: NostrEvent): boolean {
    const dTag = getTagValue(event, 'd') ?? null;
    const aTag = getTagValue(event, 'a') ?? null;
    const expiresTag = getTagValue(event, 'expiration');
    const expiresAt = expiresTag ? parseInt(expiresTag, 10) : null;
    
    // Handle replaceable events (kinds 10000-19999 and 0, 3)
    if (this.isReplaceable(event.kind)) {
      this.db.prepare(`
        DELETE FROM events 
        WHERE kind = ? AND pubkey = ? AND (created_at < ? OR (created_at = ? AND id < ?))
      `).run(event.kind, event.pubkey, event.created_at, event.created_at, event.id);
    }
    
    // Handle parameterized replaceable events (kinds 30000-39999)
    if (this.isParameterizedReplaceable(event.kind) && dTag !== null) {
      this.db.prepare(`
        DELETE FROM events 
        WHERE kind = ? AND pubkey = ? AND d_tag = ? AND (created_at < ? OR (created_at = ? AND id < ?))
      `).run(event.kind, event.pubkey, dTag, event.created_at, event.created_at, event.id);
    }
    
    try {
      this.db.prepare(`
        INSERT OR IGNORE INTO events (id, pubkey, created_at, kind, tags, content, sig, d_tag, a_tag, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        event.id,
        event.pubkey,
        event.created_at,
        event.kind,
        JSON.stringify(event.tags),
        event.content,
        event.sig,
        dTag,
        aTag,
        expiresAt
      );
      
      // Index credentials
      if (event.kind === EVENT_KINDS.CREDENTIAL_GRANT) {
        this.indexCredential(event);
      }
      
      // Cache schemas
      if (event.kind === EVENT_KINDS.CREDENTIAL_SCHEMA) {
        this.cacheSchema(event);
      }
      
      // Handle revocations
      if (event.kind === EVENT_KINDS.CREDENTIAL_REVOCATION) {
        this.processRevocation(event);
      }
      
      // Handle renewals
      if (event.kind === EVENT_KINDS.CREDENTIAL_RENEWAL) {
        this.processRenewal(event);
      }
      
      return true;
    } catch {
      return false;
    }
  }
  
  /**
   * Index a credential for fast lookups
   */
  private indexCredential(event: NostrEvent): void {
    const schemaRef = getTagValue(event, 'a');
    const classId = getTagValue(event, 'class');
    const recipient = getTagValue(event, 'p');
    const issuedAt = getTagValue(event, 'issued');
    const expiresAt = getTagValue(event, 'expires');
    const chainRef = getTagValue(event, 'chain');
    
    if (!schemaRef || !classId || !recipient || !issuedAt) return;
    
    const expires = expiresAt === 'perpetual' ? null : parseInt(expiresAt ?? '0', 10) || null;
    
    this.db.prepare(`
      INSERT OR REPLACE INTO credentials 
      (event_id, schema_ref, class_id, recipient, issuer, issued_at, expires_at, chain_ref, revoked)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).run(
      event.id,
      schemaRef,
      classId,
      recipient,
      event.pubkey,
      parseInt(issuedAt, 10),
      expires,
      chainRef ?? null
    );
  }
  
  /**
   * Cache schema for validation
   */
  private cacheSchema(event: NostrEvent): void {
    const dTag = getTagValue(event, 'd');
    if (!dTag) return;
    
    const ref = `30300:${event.pubkey}:${dTag}`;
    
    this.db.prepare(`
      INSERT OR REPLACE INTO schemas (ref, pubkey, d_tag, content, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(ref, event.pubkey, dTag, event.content, event.created_at);
  }
  
  /**
   * Process credential revocation
   */
  private processRevocation(event: NostrEvent): void {
    const aTag = getTagValue(event, 'a');
    const reason = getTagValue(event, 'reason') ?? 'unspecified';
    
    if (!aTag) return;
    
    // Parse credential reference
    const parts = aTag.split(':');
    if (parts.length < 3 || parts[0] !== '30301') return;
    
    const credentialId = parts[2];
    
    this.db.prepare(`
      UPDATE credentials 
      SET revoked = 1, revoked_at = ?, revoke_reason = ?
      WHERE event_id = ?
    `).run(event.created_at, reason, credentialId);
  }
  
  /**
   * Process credential renewal
   */
  private processRenewal(event: NostrEvent): void {
    const aTag = getTagValue(event, 'a');
    const newExpires = getTagValue(event, 'expires');
    
    if (!aTag || !newExpires) return;
    
    const parts = aTag.split(':');
    if (parts.length < 3 || parts[0] !== '30301') return;
    
    const credentialId = parts[2];
    const expiresAt = parseInt(newExpires, 10);
    
    this.db.prepare(`
      UPDATE credentials SET expires_at = ? WHERE event_id = ? AND revoked = 0
    `).run(expiresAt, credentialId);
  }
  
  /**
   * Query events by filter
   */
  queryEvents(filter: Filter): NostrEvent[] {
    const conditions: string[] = [];
    const params: (string | number)[] = [];
    
    if (filter.ids?.length) {
      conditions.push(`id IN (${filter.ids.map(() => '?').join(',')})`);
      params.push(...filter.ids);
    }
    
    if (filter.authors?.length) {
      conditions.push(`pubkey IN (${filter.authors.map(() => '?').join(',')})`);
      params.push(...filter.authors);
    }
    
    if (filter.kinds?.length) {
      conditions.push(`kind IN (${filter.kinds.map(() => '?').join(',')})`);
      params.push(...filter.kinds);
    }
    
    if (filter['#e']?.length) {
      // Event references in tags
      const tagConditions = filter['#e'].map(() => `tags LIKE ?`).join(' OR ');
      conditions.push(`(${tagConditions})`);
      params.push(...filter['#e'].map(e => `%["e","${e}"%`));
    }
    
    if (filter['#p']?.length) {
      const tagConditions = filter['#p'].map(() => `tags LIKE ?`).join(' OR ');
      conditions.push(`(${tagConditions})`);
      params.push(...filter['#p'].map(p => `%["p","${p}"%`));
    }
    
    if (filter['#a']?.length) {
      conditions.push(`a_tag IN (${filter['#a'].map(() => '?').join(',')})`);
      params.push(...filter['#a']);
    }
    
    if (filter['#d']?.length) {
      conditions.push(`d_tag IN (${filter['#d'].map(() => '?').join(',')})`);
      params.push(...filter['#d']);
    }
    
    if (filter.since !== undefined) {
      conditions.push('created_at >= ?');
      params.push(filter.since);
    }
    
    if (filter.until !== undefined) {
      conditions.push('created_at <= ?');
      params.push(filter.until);
    }
    
    // Filter expired events
    conditions.push('(expires_at IS NULL OR expires_at > ?)');
    params.push(Math.floor(Date.now() / 1000));
    
    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = filter.limit ?? 500;
    
    const rows = this.db.prepare(`
      SELECT * FROM events ${whereClause} ORDER BY created_at DESC LIMIT ?
    `).all(...params, limit) as EventRow[];
    
    return rows.map(row => ({
      id: row.id,
      pubkey: row.pubkey,
      created_at: row.created_at,
      kind: row.kind,
      tags: JSON.parse(row.tags),
      content: row.content,
      sig: row.sig,
    }));
  }
  
  /**
   * Get credential by event ID
   */
  getCredential(eventId: string): CredentialRow | null {
    return this.db.prepare('SELECT * FROM credentials WHERE event_id = ?').get(eventId) as CredentialRow | null;
  }
  
  /**
   * Get credentials for recipient
   */
  getCredentialsByRecipient(pubkey: string): CredentialRow[] {
    return this.db.prepare('SELECT * FROM credentials WHERE recipient = ?').all(pubkey) as CredentialRow[];
  }
  
  /**
   * Get schema by reference
   */
  getSchema(ref: string): { content: string; pubkey: string } | null {
    return this.db.prepare('SELECT content, pubkey FROM schemas WHERE ref = ?').get(ref) as { content: string; pubkey: string } | null;
  }
  
  /**
   * Get event by ID
   */
  getEvent(id: string): NostrEvent | null {
    const row = this.db.prepare('SELECT * FROM events WHERE id = ?').get(id) as EventRow | null;
    if (!row) return null;
    
    return {
      id: row.id,
      pubkey: row.pubkey,
      created_at: row.created_at,
      kind: row.kind,
      tags: JSON.parse(row.tags),
      content: row.content,
      sig: row.sig,
    };
  }
  
  /**
   * Delete event (NIP-09)
   */
  deleteEvent(id: string, pubkey: string): boolean {
    const result = this.db.prepare('DELETE FROM events WHERE id = ? AND pubkey = ?').run(id, pubkey);
    return result.changes > 0;
  }
  
  private isReplaceable(kind: number): boolean {
    return kind === 0 || kind === 3 || (kind >= 10000 && kind < 20000);
  }
  
  private isParameterizedReplaceable(kind: number): boolean {
    return kind >= 30000 && kind < 40000;
  }
  
  close(): void {
    this.db.close();
  }
}
