import 'dotenv/config';
import { DojoRelay } from './relay.js';

const PORT = parseInt(process.env.RELAY_PORT ?? '8080', 10);
const DB_PATH = process.env.DB_PATH ?? './dojo-relay.db';

const relay = new DojoRelay(PORT, DB_PATH);

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n[Relay] Shutting down...');
  relay.close();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n[Relay] Shutting down...');
  relay.close();
  process.exit(0);
});
