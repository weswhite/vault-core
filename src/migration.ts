/**
 * Sealing a history that already exists.
 *
 * The walk and the payload it builds, shared by every client that can encrypt a
 * user's past: the rules for which fields go into a record are the same whether
 * the user enrolled on the phone or on the web, and a field left out of the
 * payload is not hidden but deleted.
 *
 * Pure. Transport and sealing are injected, so neither this module nor its
 * tests ever touch a network or a key.
 */

export {
  MIGRATION_TABLES,
  PRIVATE_FIELDS,
  REQUIRES_CELL,
  preparePayload,
  type MigrationRow,
  type MigrationTable,
  type PreparedRow,
} from './migration/payload';

export {
  MigrationCancelled,
  runMigration,
  type ApplyItem,
  type MigrationPage,
  type MigrationPhase,
  type MigrationProgress,
  type MigrationResult,
  type MigrationTransport,
  type SealedRow,
  type Sealer,
} from './migration/walk';
