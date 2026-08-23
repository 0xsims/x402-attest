import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import {
  createTap,
  isAnchored,
  withAttestation,
  type AnyReceipt,
  type AttestOptions,
  type AttestedFetch,
  type FetchLike,
} from '@rubric-protocol/x402-attest';

/**
 * ClawRouter attestation wiring.
 *
 * ClawRouter is MIT-licensed, runs a local OpenAI-compatible x402 proxy on port
 * 8402, and already emits `x-clawrouter-*` routing headers describing which model
 * it picked. That is most of the evidence an auditor needs; what is missing is a
 * tamper-evident record binding those routing decisions to the payments that were
 * made for them.
 *
 * This is complementary, not adversarial. ClawRouter's pitch is that it saves you
 * money by routing to a cheaper model that is good enough. That is a claim about
 * substitution, and the honest way to back a substitution claim is to make the
 * substitutions independently checkable. Attaching receipts turns "we saved you
 * 92%" from a dashboard number into something a buyer's auditor can verify without
 * asking either BlockRun or Rubric to vouch for it.
 *
 * Two wirings are provided because ClawRouter has two integration surfaces:
 *
 *   1. `withClawRouterAttestation` — wrap the fetch your agent already uses to
 *      call localhost:8402. One line, no ClawRouter change, no extra hop.
 *   2. `createAttestingProxy` — an attesting reverse proxy that sits in front of
 *      ClawRouter and adds the Rubric response headers. Use this when the client
 *      cannot be changed, or when several clients share one router.
 */

/** Headers ClawRouter emits. The SDK's allowlist already captures the whole prefix. */
export const CLAWROUTER_HEADERS = [
  'x-clawrouter-profile',
  'x-clawrouter-tier',
  'x-clawrouter-model',
  'x-clawrouter-confidence',
  'x-clawrouter-reasoning',
] as const;

export const DEFAULT_CLAWROUTER_PORT = 8402;
export const DEFAULT_CLAWROUTER_URL = `http://127.0.0.1:${DEFAULT_CLAWROUTER_PORT}`;

export type ClawRouterAttestOptions = Omit<AttestOptions, 'subjectId'> & {
  subjectId?: string;
};

/**
 * Wrap a fetch pointed at ClawRouter.
 *
 * The tap is installed by default. Without it the 402 handshake happens inside
 * ClawRouter's proxy and the price and payee assertions would all be `unknown` —
 * which is exactly the evidence a routing audit needs most.
 */
export function withClawRouterAttestation<F extends FetchLike>(
  baseFetch: F,
  options: ClawRouterAttestOptions = {},
): AttestedFetch<F> {
  const tap = options.tap ?? createTap();
  return withAttestation(tap.wrapFetch(baseFetch) as F, {
    ...options,
    subjectId: options.subjectId ?? 'clawrouter',
    tap,
    // The routing headers are the point, so metadata mode is not forced on: the
    // model comparison still runs under hash-only, it just records digests. Left
    // to the caller.
  });
}

export type AttestingProxyOptions = ClawRouterAttestOptions & {
  /** Port this proxy listens on. Deliberately not 8402 — ClawRouter owns that. */
  listenPort?: number;
  /** Upstream ClawRouter base URL. */
  upstream?: string;
  /** Injected for tests. */
  fetchImpl?: FetchLike;
};

export type AttestingProxy = {
  server: Server;
  attestedFetch: AttestedFetch;
  port: number;
  close: () => Promise<void>;
};

/**
 * Headers that belong to a single transport hop and must not be relayed.
 * `content-encoding` is dropped too: the body has already been decoded by the
 * time we hold it, so advertising the original encoding would be a lie.
 */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'content-length',
  'content-encoding',
]);

function collectBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * Reverse proxy that attests everything it forwards to ClawRouter.
 *
 * Adds `x-rubric-attestation-id` and `x-rubric-receipt-url` when the call's batch
 * is already anchored, and omits them otherwise. It never waits for anchoring:
 * batches anchor on a 60s / 256-leaf schedule, and holding an LLM response for up
 * to a minute to decorate it with a header would be an absurd trade.
 *
 * `x-rubric-call-id` is always present. That is the durable handle — a client can
 * retrieve the full receipt by call id once the batch anchors, so nothing is lost
 * by omitting the other two.
 */
export function createAttestingProxy(options: AttestingProxyOptions = {}): AttestingProxy {
  const upstream = (options.upstream ?? DEFAULT_CLAWROUTER_URL).replace(/\/+$/, '');
  const tap = options.tap ?? createTap();
  const base = (options.fetchImpl ?? (globalThis.fetch as FetchLike));

  let lastCallId: string | null = null;
  const attestedFetch = withAttestation(tap.wrapFetch(base), {
    ...options,
    subjectId: options.subjectId ?? 'clawrouter-proxy',
    tap,
    onReceipt: (r: AnyReceipt) => {
      lastCallId = r.callRecord.callId;
      options.onReceipt?.(r);
    },
  });

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const body = await collectBody(req);
        const headers = new Headers();
        for (const [k, v] of Object.entries(req.headers)) {
          if (v === undefined) continue;
          // `host` must not be forwarded: it would point the upstream at us.
          if (k === 'host' || k === 'connection' || k === 'content-length') continue;
          headers.set(k, Array.isArray(v) ? v.join(', ') : v);
        }

        const method = req.method ?? 'GET';
        const init: RequestInit = { method, headers };
        if (method !== 'GET' && method !== 'HEAD' && body.byteLength > 0) {
          init.body = body;
        }

        lastCallId = null;
        const upstreamRes = await attestedFetch(`${upstream}${req.url ?? '/'}`, init);
        // `onReceipt` fires synchronously during the wrapper's commit, so by the
        // time the response is in hand the call id is known.
        const callId = lastCallId;

        const outHeaders: Record<string, string> = {};
        upstreamRes.headers.forEach((value, key) => {
          // Hop-by-hop headers describe the connection we just terminated, not
          // the message. Forwarding `transfer-encoding: chunked` alongside the
          // `content-length` we set below produces a response that violates
          // HTTP/1.1 and that undici refuses to parse at all.
          if (HOP_BY_HOP.has(key.toLowerCase())) return;
          outHeaders[key] = value;
        });

        if (callId) {
          outHeaders['x-rubric-call-id'] = callId;
          const receipt = attestedFetch.getReceipt(callId);
          if (receipt && isAnchored(receipt)) {
            outHeaders['x-rubric-attestation-id'] = receipt.attestationId;
            outHeaders['x-rubric-receipt-url'] = receipt.verifyUrl;
          }
        }

        const payload = Buffer.from(await upstreamRes.arrayBuffer());
        outHeaders['content-length'] = String(payload.byteLength);
        res.writeHead(upstreamRes.status, outHeaders);
        res.end(payload);
      } catch (e) {
        // A proxy failure is still a call the buyer made. It is already attested by
        // the wrapper; here we just have to answer the client.
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { message: `attesting proxy: ${(e as Error).message}` } }));
      }
    })();
  });

  const listenPort = options.listenPort ?? 8403;
  server.listen(listenPort);

  return {
    server,
    attestedFetch,
    port: listenPort,
    close: async () => {
      await attestedFetch.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/**
 * Adapter for ClawRouter's `startProxy` callbacks.
 *
 * `onRouted` and `onPayment` report routing and payment events out of band. They
 * carry no request identity we can correlate against, so they are recorded as
 * context rather than folded into a call record — inventing a correlation would
 * put a guess into an audit artifact.
 */
export function createRoutingObserver(): {
  onRouted: (info: unknown) => void;
  onPayment: (info: unknown) => void;
  events: { at: string; kind: 'routed' | 'payment'; info: unknown }[];
} {
  const events: { at: string; kind: 'routed' | 'payment'; info: unknown }[] = [];
  return {
    events,
    onRouted: (info) => events.push({ at: new Date().toISOString(), kind: 'routed', info }),
    onPayment: (info) => events.push({ at: new Date().toISOString(), kind: 'payment', info }),
  };
}

/** Convenience for a Node http proxy that forwards without fetch. Used by tests. */
export function forwardRaw(
  upstreamUrl: string,
  req: IncomingMessage,
  res: ServerResponse,
): void {
  const target = new URL(upstreamUrl);
  const proxied = httpRequest(
    {
      hostname: target.hostname,
      port: target.port,
      path: req.url,
      method: req.method,
      headers: { ...req.headers, host: target.host },
    },
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
      upstreamRes.pipe(res);
    },
  );
  proxied.on('error', () => {
    res.writeHead(502);
    res.end();
  });
  req.pipe(proxied);
}
