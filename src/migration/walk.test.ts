/**
 * The migration loop.
 *
 * A fake server that behaves like the real one where it matters: it only ever
 * hands out rows that are still unsealed, keyed forward by a cursor, and it
 * skips rows that are already sealed. Most of what is tested is how the loop
 * ends -- because it will be interrupted, and every way it stops has to leave a
 * state that the next walk simply finishes.
 */

import { describe, it, expect, vi } from 'vitest';
import { runMigration, MigrationCancelled, type MigrationTransport, type ApplyItem } from './walk';
import { REQUIRES_CELL, preparePayload, type MigrationRow, type MigrationTable } from './payload';

type Row = MigrationRow & { table: MigrationTable; sealed: boolean; poison?: boolean };

function makeServer(rows: Row[], pageSize = 2) {
  const applied: ApplyItem[] = [];
  const calls: string[] = [];

  const unsealed = () => rows.filter((r) => !r.sealed);

  const transport: MigrationTransport = {
    claim: vi.fn(async () => {
      calls.push('claim');
    }),
    next: vi.fn(async (cursor: string | null) => {
      calls.push(`next:${cursor ?? 'null'}`);
      const after = cursor ? Number(cursor) : -1;
      const all = rows.map((r, i) => ({ r, i })).filter(({ r, i }) => !r.sealed && i > after);
      if (all.length === 0) return { table: 'UplandBirdShot' as const, rows: [], nextCursor: null, done: true };
      // One table per page, like the real walk.
      const table = all[0].r.table;
      const page = all.filter(({ r }) => r.table === table).slice(0, pageSize);
      return {
        table,
        rows: page.map(({ r }) => r),
        nextCursor: String(page[page.length - 1].i),
        done: false,
      };
    }),
    apply: vi.fn(async (items: ApplyItem[]) => {
      calls.push(`apply:${items.length}`);
      let applied_ = 0;
      let skipped = 0;
      for (const item of items) {
        const row = rows.find((r) => r.id === item.id)!;
        if (row.sealed) {
          skipped += 1;
          continue;
        }
        row.sealed = true;
        applied.push(item);
        applied_ += 1;
      }
      return { applied: applied_, skipped, failed: 0 };
    }),
    finish: vi.fn(async () => {
      calls.push('finish');
      const remaining = unsealed().length;
      return { status: remaining === 0 ? 'complete' : 'running', remaining };
    }),
    remaining: vi.fn(async () => ({ initial: unsealed().length, reencrypt: 0 })),
  };

  return { transport, applied, calls };
}

const row = (id: string, table: MigrationTable = 'FishCatch', extra: Partial<Row> = {}): Row => ({
  id,
  table,
  latitude: 45.1,
  longitude: -111.6,
  species: 'Brown trout',
  createdAt: '2026-01-01T00:00:00.000Z',
  sealed: false,
  ...extra,
});

/** Seals everything except rows marked poison. */
const sealer = (rows: Row[]) =>
  vi.fn(async (_table: MigrationTable, prepared: Array<{ id: string }>) =>
    prepared.map((p) =>
      rows.find((r) => r.id === p.id)?.poison
        ? { id: p.id, failed: true }
        : { id: p.id, encBlob: `sealed:${p.id}`, geohash4: 'c2cy' },
    ),
  );

describe('a clean walk', () => {
  it('seals everything, table by table, and lets the server say it is done', async () => {
    const rows = [row('s1', 'Spot'), row('f1'), row('f2'), row('f3')];
    const { transport, applied } = makeServer(rows);

    const result = await runMigration({ transport, seal: sealer(rows), deviceId: 'd', envelopeVersion: 1 });

    expect(applied.map((a) => a.id)).toEqual(['s1', 'f1', 'f2', 'f3']);
    expect(result).toMatchObject({ sealed: 4, failed: 0, remaining: 0, complete: true });
  });

  it('claims the lease before touching anything', async () => {
    const rows = [row('f1')];
    const { transport, calls } = makeServer(rows);
    await runMigration({ transport, seal: sealer(rows), deviceId: 'd', envelopeVersion: 1 });

    expect(calls[0]).toBe('claim');
    expect(calls.at(-1)).toBe('finish');
  });

  it('sends ciphertext with its cell and envelope version, nothing else', async () => {
    const rows = [row('f1')];
    const { transport, applied } = makeServer(rows);
    await runMigration({ transport, seal: sealer(rows), deviceId: 'd', envelopeVersion: 1 });

    expect(applied[0]).toEqual({
      table: 'FishCatch',
      id: 'f1',
      encVersion: 1,
      encBlob: 'sealed:f1',
      geohash4: 'c2cy',
    });
  });

  it('renews the lease on long walks', async () => {
    const rows = Array.from({ length: 50 }, (_, i) => row(`f${i}`));
    const { transport } = makeServer(rows, 2);
    await runMigration({ transport, seal: sealer(rows), deviceId: 'd', envelopeVersion: 1 });

    // 25 pages: the initial claim plus one renewal at page 20.
    expect(transport.claim).toHaveBeenCalledTimes(2);
  });
});

describe('rows that will not seal', () => {
  it('skips them, keeps going, and reports them', async () => {
    const rows = [row('f1'), row('f2', 'FishCatch', { poison: true }), row('f3')];
    const { transport, applied } = makeServer(rows);

    const result = await runMigration({ transport, seal: sealer(rows), deviceId: 'd', envelopeVersion: 1 });

    expect(applied.map((a) => a.id)).toEqual(['f1', 'f3']);
    expect(result.failed).toBe(1);
  });

  it('does not loop forever on a page where nothing seals', async () => {
    // The rows stay unsealed, so the server would hand them out again if the
    // cursor did not move. It moves regardless of what happened to them.
    const rows = [row('f1', 'FishCatch', { poison: true }), row('f2', 'FishCatch', { poison: true })];
    const { transport } = makeServer(rows);

    const result = await runMigration({ transport, seal: sealer(rows), deviceId: 'd', envelopeVersion: 1 });

    expect(transport.next).toHaveBeenCalledTimes(2);
    expect(result).toMatchObject({ sealed: 0, failed: 2, remaining: 2, complete: false });
  });

  it('trusts the server recount, not its own tally, for "complete"', async () => {
    const rows = [row('f1'), row('f2', 'FishCatch', { poison: true })];
    const { transport } = makeServer(rows);
    const result = await runMigration({ transport, seal: sealer(rows), deviceId: 'd', envelopeVersion: 1 });

    expect(result.complete).toBe(false);
    expect(result.remaining).toBe(1);
  });

  it('picks the failures up on the next walk, which starts from the top', async () => {
    const rows = [row('f1'), row('f2', 'FishCatch', { poison: true })];
    const { transport } = makeServer(rows);
    await runMigration({ transport, seal: sealer(rows), deviceId: 'd', envelopeVersion: 1 });

    rows[1].poison = false;
    const second = await runMigration({ transport, seal: sealer(rows), deviceId: 'd', envelopeVersion: 1 });

    expect(second).toMatchObject({ sealed: 1, remaining: 0, complete: true });
  });
});

describe('interruption', () => {
  it('stops between pages when aborted, keeping what was sealed', async () => {
    const rows = [row('f1'), row('f2'), row('f3'), row('f4')];
    const { transport, applied } = makeServer(rows, 2);
    const abort = new AbortController();

    const walk = runMigration({
      transport,
      seal: sealer(rows),
      deviceId: 'd',
      envelopeVersion: 1,
      signal: abort.signal,
      onProgress: () => abort.abort(),
    });

    await expect(walk).rejects.toBeInstanceOf(MigrationCancelled);
    expect(applied.map((a) => a.id)).toEqual(['f1', 'f2']);
    expect(transport.finish).not.toHaveBeenCalled();
  });

  it('resumes by simply walking again', async () => {
    const rows = [row('f1'), row('f2'), row('f3'), row('f4')];
    const { transport } = makeServer(rows, 2);
    const abort = new AbortController();
    await runMigration({
      transport,
      seal: sealer(rows),
      deviceId: 'd',
      envelopeVersion: 1,
      signal: abort.signal,
      onProgress: () => abort.abort(),
    }).catch(() => {});

    const second = await runMigration({ transport, seal: sealer(rows), deviceId: 'd', envelopeVersion: 1 });
    expect(second).toMatchObject({ sealed: 2, remaining: 0, complete: true });
  });

  it('surfaces a refusal from the server instead of swallowing it', async () => {
    // A 402 mid-walk is a lapsed subscription: stop, and leave a valid partial
    // state. The walk must not treat it as "nothing left".
    const rows = [row('f1'), row('f2'), row('f3')];
    const { transport } = makeServer(rows, 1);
    let n = 0;
    transport.apply = vi.fn(async () => {
      n += 1;
      if (n === 2) throw Object.assign(new Error('lapsed'), { status: 402 });
      return { applied: 1, skipped: 0, failed: 0 };
    });

    await expect(
      runMigration({ transport, seal: sealer(rows), deviceId: 'd', envelopeVersion: 1 }),
    ).rejects.toThrow('lapsed');
  });
});

describe('a table this client has never heard of', () => {
  it('skips it and keeps walking, rather than stranding the whole history', async () => {
    // Guessing its fields would delete whichever ones we missed. Failing the
    // run would strand every older app on the store the day a table is added.
    // 'Debrief' stands in for that; it used to be 'Read', until Read became a
    // real migration table.
    const { transport, applied } = makeServer([]);
    let served = 0;
    transport.next = vi.fn(async () => {
      served += 1;
      if (served > 1) return { table: 'Spot' as MigrationTable, rows: [], nextCursor: null, done: true };
      return { table: 'Debrief' as MigrationTable, rows: [row('x')], nextCursor: '0', done: false };
    });
    const seal = vi.fn();

    const result = await runMigration({
      transport,
      seal,
      deviceId: 'd',
      envelopeVersion: 1,
    });

    expect(seal).not.toHaveBeenCalled();
    expect(applied).toHaveLength(0);
    expect(result.failed).toBe(1);
    // The cursor moved past it, so the walk reached the end rather than
    // serving that page forever.
    expect(transport.next).toHaveBeenCalledTimes(2);
  });
});

describe('a Read', () => {
  it('seals its point, note and title, and nothing else', () => {
    // A Read is the one table whose columns are named differently, so the
    // server renames them into the common row shape before they get here. This
    // is the test that the renaming and this file agree; if they ever stop, a
    // migrated Read loses its note permanently.
    const prepared = preparePayload('Read', {
      id: 'r1',
      latitude: 45.678912,
      longitude: -111.042934,
      notes: 'practice water',
      title: 'Tuesday scout',
      createdAt: '2026-01-01T00:00:00.000Z',
    });

    expect(prepared.payload).toEqual({
      lat: 45.678912,
      lng: -111.042934,
      nt: 'practice water',
      tl: 'Tuesday scout',
    });
    expect(prepared.cellLat).toBe(45.678912);
  });

  it('seals with no position at all, because a Read may never have had one', () => {
    // Read.pointLat is nullable, unlike Spot's. Such a row still has a note
    // worth hiding, so it seals with an empty cell rather than being skipped.
    const prepared = preparePayload('Read', {
      id: 'r2',
      latitude: null,
      longitude: null,
      notes: 'the far blind',
      createdAt: '2026-01-01T00:00:00.000Z',
    });

    expect(prepared.payload).toEqual({ nt: 'the far blind' });
    expect(prepared.cellLat).toBeNull();
    expect(REQUIRES_CELL.has('Read')).toBe(false);
  });
});
