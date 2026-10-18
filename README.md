# Real-Time Phishing Domain Triage

A real-time pipeline that watches public Certificate Transparency logs,
flags newly issued certificates whose domains look like phishing lookalikes
of Indian financial brands (SBI, HDFC, ICICI, Axis, Kotak, Paytm, PhonePe,
Zerodha, Groww), and routes those candidates through an LLM classifier with
full observability.

Built as an AI + DevOps portfolio project. The emphasis is on the
production-grade LLM tier — rate-limit awareness, circuit breaker,
graceful degradation, cost accounting — not on the ML sophistication.

## Architecture

```
                  (public Certificate Transparency logs)
                                   │
                                   ▼
                 self-hosted certstream-server (Go)
                                   │  ws://:8080/full-stream
                                   ▼
                           ingester  ──►  Redis (raw_certs)
                                              │
                                              ▼
                      filter   Stage A: watchlist + Levenshtein ≤ 2
                               Stage B: 7-feature structural score
                               Stage C: MiniLM cosine similarity
                                              │  (survivors)
                                              ▼
                                   Redis (triage_candidates)
                                              │
                                   HAProxy  (round-robin, /health probes)
                                        │        │        │
                                        ▼        ▼        ▼
                              llm-worker-1  worker-2  worker-3
                                        │        │        │
                                        └────────┴────────┘
                                              │
                                   Groq API (openai/gpt-oss-20b)
                                        │
                                        ├─ 200 OK  →  verdict (source=llm)
                                        └─ breaker open / error
                                              │
                                              ▼
                                      rule-based fallback  →  verdict (source=fallback)
                                              │
                                              ▼
                                         Postgres (verdicts)

   Parallel path: every service → /metrics → Prometheus → Grafana (3 dashboards)
```

Eleven containers orchestrated via Docker Compose: `postgres`, `redis`,
`haproxy`, `prometheus`, `grafana`, `certstream-server`, `ingester`,
`filter`, `llm-worker-1/2/3`.

## Quick start

Prerequisites: Docker Desktop with WSL2 backend, ~8 GB free disk.

```bash
git clone <this-repo>
cd Real-Time-Phishing-Domain-Triage
cp .env.example .env
# Set GROQ_API_KEY in .env (free tier works)
docker compose up -d --build
```

First build takes ~8 minutes (torch + MiniLM download + certstream-server
subscribing to CT operators). Subsequent starts are seconds.

Then:
- **Grafana** → http://localhost:3000  (anonymous viewer; three provisioned dashboards)
- **Prometheus** → http://localhost:9090
- **HAProxy stats** → http://localhost:8081
- **Postgres** → `docker exec phish-postgres psql -U phish -d phish`

To see verdicts flowing:
```bash
docker exec phish-postgres psql -U phish -d phish \
  -c "SELECT verdict, domain, matched_brand, source, confidence, LEFT(reasoning, 100) \
      FROM verdicts WHERE source='llm' ORDER BY id DESC LIMIT 10;"
```

## What it does

- **Ingester** subscribes to a self-hosted certstream-server (which itself
  reads directly from Google Argon, Cloudflare Nimbus, Let's Encrypt Oak,
  Sectigo, and DigiCert CT logs). Receives ~200–400 certs/sec during peak.
- **Filter** drops ~99.95% in three progressive stages:
  1. Levenshtein distance ≤ 2 of brand token (cheap, ~10 µs)
  2. Weighted structural score across 7 features — subdomain depth, hyphen
     count, digit ratio, length, risky TLD, punycode, cert age (~50 µs)
  3. MiniLM cosine similarity against pre-computed brand embeddings (~5 ms)
- **LLM worker tier** pulls survivors off Redis and asks Groq to classify
  as `phishing` / `suspicious` / `benign` with reasoning. The tier has the
  full production kit:
  - **Token-aware rate limiter** reads Groq's own response headers
    (`x-ratelimit-remaining-tokens`, `x-ratelimit-reset-tokens`) and
    pre-waits when margin is thin
  - **10-second hard timeout** per call
  - **3 retries with exponential backoff** honouring `Retry-After` on 429s
  - **Circuit breaker** (`closed → open → half-open`) that trips on
    sustained failures and short-circuits the LLM path
  - **Rule-based fallback classifier** when the breaker is open — a
    weighted vote over the filter signals the pipeline already computed.
    Verdicts still land in Postgres, tagged `source=fallback`.
- **Postgres** stores every verdict with full lineage: domain, cert issuer,
  three filter scores, matched brand, verdict, confidence, reasoning,
  model version, source.

## Observability

Every service exports Prometheus metrics on a dedicated port.

Three provisioned Grafana dashboards:

- **Pipeline Health** — ingest rate, queue depths, drops by stage/reason,
  WebSocket reconnects.
- **LLM Tier** — requests/second by status (ok / 429 / 5xx / timeout),
  latency p50/p95/p99, tokens/min, Groq quota remaining, breaker state.
- **Business** — verdicts/minute by class, LLM vs fallback share, flagged
  brands.

Prometheus alerts (`infra/prometheus/alerts.yml`):

- `QueueDepthHigh` — raw or triage queue > 1000 for 5 minutes
- `LLMErrorRateHigh` — > 20% non-ok responses over 2 minutes
- `AllBreakersOpen` — every worker's breaker open at once (critical)
- `IngestionStalled` — no certs ingested for 2+ minutes


## Repository layout

```
.
├── docker-compose.yml           # 11 services, dev override at .override
├── services/
│   ├── ingester/                # Certstream WS → Redis
│   ├── filter/                  # Stage A/B/C
│   ├── llm-worker/              # Groq client + breaker + limiter + fallback
│   └── api/                     # (reserved — not built yet)
├── infra/
│   ├── haproxy/haproxy.cfg
│   ├── prometheus/{prometheus.yml, alerts.yml}
│   └── grafana/{provisioning/, dashboards/}
└── .env.example
```

## Known limits

**Honest about what this is and isn't.**

- **Free-tier Groq TPM caps the LLM path at ~7–10 classifications/min.**
  Everything over that is handled by the rule-based fallback, which is
  the entire point of the fallback existing. On a paid tier the limiter
  gets out of the way and throughput scales linearly with workers.
- **Stage A watchlist is lenient on short brand names** ("sbi" matches
  far too many hex substrings). The LLM is the real judge; tightening
  Stage A would reduce false positive triage load but is a tuning
  exercise, not a design flaw.
- **Filter is CPU-bound and can't keep up with CT firehose at steady
  state.** Queue depth grows during traffic spikes. Fixable via batched
  MiniLM inference or horizontal filter scaling; left as a known limit.
- **No frontend yet.** Grafana is the operator UI. A FastAPI + React SPA
  is scoped in `docker-compose.yml` for future work.
- **No multi-user auth, no mobile, no Kubernetes.** Single-operator LAN
  tool by design.

## What I'd do differently

- Share the rate limiter across workers via Redis (currently per-worker,
  so three workers each race their own view of remaining TPM).
- Batch Stage C embedding inference (per-call MiniLM is wasteful at
  scale).
- Tighten Stage A to require matched brand length ≥ 4 chars OR a
  non-UUID-looking token.
- Add a verdict-dedup cache so the same domain hitting multiple CT logs
  in a window only burns one LLM call.

## Stack

Python 3.12 • aiohttp • asyncpg • redis-py • httpx • sentence-transformers
(MiniLM-L6-v2, CPU) • Postgres 16 • Redis 7 • HAProxy • Prometheus •
Grafana • Groq (openai/gpt-oss-20b) • Docker Compose

## License

MIT.
