/**
 * Sealing a user's existing history, one page at a time.
 *
 * Built around interruption, like the server side: a tab closes, a laptop
 * sleeps, a request drops. Every step is idempotent -- the server skips rows it
 * has already sealed -- and resuming is simply starting again. The server only
 * ever hands out rows that are still unsealed, so a fresh walk from the top
 * picks up exactly what is left, including anything that failed last time.
 *
 * Transport and sealing are injected, so the loop can be tested without a
 * network or a Worker. Neither ever sees a key.
 */

import {
  MIGRATION_TABLES,
  REQUIRES_CELL,
  preparePayload,
  type MigrationRow,
  type MigrationTable,
} from './payload';

/**
 * One row back from whatever did the sealing: a worker on the web, the vault
 * session on the phone. `failed` rather than an exception, so one row that will
 * not seal does not take the page with it.
 */
export interface SealedRow {
  id: string;
  encBlob?: string;
  geohash4?: string | null;
  failed?: boolean;
}

export type MigrationPhase = 'initial' | 'reencrypt';

export interface MigrationPage {
  table: MigrationTable;
  rows: MigrationRow[];
  nextCursor: string | null;
  done: boolean;
}

export interface ApplyItem {
  table: MigrationTable;
  id: string;
  encVersion: number;
  encBlob: string;
  geohash4?: string | null;
}

export interface MigrationTransport {
  claim(deviceId: string): Promise<void>;
  next(cursor: string | null, phase: MigrationPhase): Promise<MigrationPage>;
  apply(items: ApplyItem[], cursor: string | null, phase: MigrationPhase): Promise<{ applied: number; skipped: number; failed: number }>;
  finish(phase: MigrationPhase): Promise<{ status: string; remaining: number }>;
  /** Read-only counts of what is still unsealed. */
  remaining(): Promise<{ initial: number; reencrypt: number }>;
}

export type Sealer = (
  table: MigrationTable,
  rows: ReturnType<typeof preparePayload>[],
) => Promise<SealedRow[]>;

export interface MigrationProgress {
  sealed: number;
  /** Rows that could not be sealed or were refused. They stay plaintext. */
  failed: number;
  table: MigrationTable | null;
}

export interface MigrationResult {
  sealed: number;
  failed: number;
  /** The server's own recount. The only number that means "done". */
  remaining: number;
  complete: boolean;
}

/** Pages between lease renewals. The lease is ten minutes; this is far inside it. */
const RENEW_EVERY = 20;

/**
 * Just enough of AbortSignal to stop a walk.
 *
 * Structural on purpose: a browser AbortSignal satisfies it, and so does React
 * Native's, without this package depending on DOM types it otherwise has no use
 * for.
 */
export interface StopSignal {
  readonly aborted: boolean;
}

export class MigrationCancelled extends Error {
  constructor() {
    super('Migration stopped');
    this.name = 'MigrationCancelled';
  }
}

export async function runMigration(opts: {
  transport: MigrationTransport;
  seal: Sealer;
  deviceId: string;
  envelopeVersion: number;
  phase?: MigrationPhase;
  onProgress?: (p: MigrationProgress) => void;
  signal?: StopSignal;
}): Promise<MigrationResult> {
  const { transport, seal, deviceId, envelopeVersion, onProgress, signal } = opts;
  const phase = opts.phase ?? 'initial';

  await transport.claim(deviceId);

  let cursor: string | null = null;
  let sealedTotal = 0;
  let failedTotal = 0;
  let pages = 0;

  for (;;) {
    if (signal?.aborted) throw new MigrationCancelled();

    const page = await transport.next(cursor, phase);
    if (page.done || page.rows.length === 0) break;

    if (!MIGRATION_TABLES.includes(page.table)) {
      /*
       * A table added to the server after this client shipped.
       *
       * Sealing it is out of the question -- guessing its fields would delete
       * whichever ones we missed -- but so is failing the whole walk, which
       * would strand every older app on the store the day a table is added.
       * So it is skipped exactly like an unsealable row: nothing applied, the
       * cursor moved past it, the rows counted as failed and left readable.
       * The server's recount reports them, and whichever client does know the
       * table finishes the job.
       */
      await transport.apply([], page.nextCursor, phase);
      failedTotal += page.rows.length;
      onProgress?.({ sealed: sealedTotal, failed: failedTotal, table: null });
      cursor = page.nextCursor;
      pages += 1;
      if (pages % RENEW_EVERY === 0) await transport.claim(deviceId);
      continue;
    }

    const prepared = page.rows.map((row) => preparePayload(page.table, row));

    // A Spot or Observation with no position cannot be sealed: the server needs
    // a cell for the NOT NULL coordinate columns. Skipped here rather than sent
    // to be refused; it stays plaintext and the recount reports it.
    const sealable = prepared.filter(
      (p) => !REQUIRES_CELL.has(page.table) || (p.cellLat != null && p.cellLng != null),
    );
    const unsealable = prepared.length - sealable.length;

    const sealed = sealable.length > 0 ? await seal(page.table, sealable) : [];
    const items: ApplyItem[] = [];
    let sealFailures = 0;
    for (const row of sealed) {
      if (row.failed || !row.encBlob) {
        sealFailures += 1;
        continue;
      }
      items.push({
        table: page.table,
        id: row.id,
        encVersion: envelopeVersion,
        encBlob: row.encBlob,
        geohash4: row.geohash4 ?? null,
      });
    }

    // Applied even when empty, so the server's record of the walk (status, last
    // cursor) stays current. Progress itself does not depend on it: the cursor
    // lives here, and moves past this page whatever happened to its rows. That
    // is also what keeps a page of unsealable rows from looping forever -- they
    // come back only on the next walk, which starts from the top.
    const result = await transport.apply(items, page.nextCursor, phase);

    sealedTotal += result.applied;
    failedTotal += result.failed + sealFailures + unsealable;
    onProgress?.({ sealed: sealedTotal, failed: failedTotal, table: page.table });

    cursor = page.nextCursor;
    pages += 1;
    if (pages % RENEW_EVERY === 0) await transport.claim(deviceId);
  }

  const finished = await transport.finish(phase);
  return {
    sealed: sealedTotal,
    failed: failedTotal,
    remaining: finished.remaining,
    complete: finished.status === 'complete',
  };
}
