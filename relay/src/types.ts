// NOSTR Event Types

export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export interface UnsignedEvent {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}

// NIP-XXX Credential Types

export interface CredentialClass {
  name: string;
  description?: string;
  scope: string[];
  issued_by: string[];
  expiry: {
    max_days: number | null;
    renewable: boolean;
  };
  cascade_revoke: boolean;
  constraints?: Record<string, unknown>;
}

export interface CredentialSchema {
  classes: Record<string, CredentialClass>;
}

export interface CredentialContent {
  restrictions?: string[];
  evidence?: string;
  notes?: string;
}

// Event Kinds
export const EVENT_KINDS = {
  // Standard NOSTR
  METADATA: 0,
  TEXT_NOTE: 1,
  CONTACTS: 3,
  DM: 4,
  DELETE: 5,
  
  // NIP-58 Badges
  BADGE_DEFINITION: 30009,
  BADGE_AWARD: 8,
  PROFILE_BADGES: 30008,
  
  // NIP-XXX Hierarchical Credentials
  CREDENTIAL_SCHEMA: 30100,
  CREDENTIAL_GRANT: 30101,
  CREDENTIAL_REVOCATION: 30102,
  CREDENTIAL_RENEWAL: 30103,
} as const;

// Verification Results
export type VerificationResult = 
  | { status: 'VALID'; chain_depth: number }
  | { status: 'INVALID'; reason: string }
  | { status: 'EXPIRED'; expired_at: number }
  | { status: 'REVOKED'; revoked_at: number; reason: string };

// Client Messages
export type ClientMessage =
  | ['EVENT', NostrEvent]
  | ['REQ', string, ...Filter[]]
  | ['CLOSE', string];

// Relay Messages
export type RelayMessage =
  | ['EVENT', string, NostrEvent]
  | ['OK', string, boolean, string]
  | ['EOSE', string]
  | ['NOTICE', string]
  | ['CLOSED', string, string];

// Subscription Filters
export interface Filter {
  ids?: string[];
  authors?: string[];
  kinds?: number[];
  '#e'?: string[];
  '#p'?: string[];
  '#a'?: string[];
  '#d'?: string[];
  since?: number;
  until?: number;
  limit?: number;
}

// Database Row Types
export interface EventRow {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string;
  content: string;
  sig: string;
  d_tag: string | null;
  a_tag: string | null;
  expires_at: number | null;
}

export interface CredentialRow {
  event_id: string;
  schema_ref: string;
  class_id: string;
  recipient: string;
  issuer: string;
  issued_at: number;
  expires_at: number | null;
  chain_ref: string | null;
  revoked: number;
  revoked_at: number | null;
  revoke_reason: string | null;
}
