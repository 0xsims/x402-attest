/**
 * Child process for the crash-recovery test.
 *
 * Writes N leaves and then SIGKILLs itself mid-batch: no flush, no close, no
 * signal handler, no chance to tidy up. Whatever survives is what the WAL's
 * durability guarantee is actually worth.
 */
import { writeSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const [distPath, walPath, countArg, fsyncPolicy] = process.argv.slice(2);
const { withAttestation } = await import(pathToFileURL(distPath).href);

const upstream = async () =>
  new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });

const wrapped = withAttestation(upstream, {
  subjectId: 'crash-agent',
  sessionId: 'crash-session',
  walPath,
  mode: 'batch',
  // Big enough that nothing auto-flushes: the process dies with a full queue.
  batch: { maxLeaves: 100000, maxAgeMs: 600000 },
  wal: { fsync: fsyncPolicy ?? 'always' },
  installSignalHandlers: false,
  policy: { maxPricePerCall: '1.00', allowedNetworks: ['eip155:8453'] },
});

const count = Number(countArg);
for (let i = 0; i < count; i++) {
  const res = await wrapped(`https://seller.example/item/${i}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ i }),
  });
  await res.arrayBuffer();
}

// writeSync, not console.log: the parent must see this before the kill lands.
writeSync(1, 'WROTE\n');
process.kill(process.pid, 'SIGKILL');
