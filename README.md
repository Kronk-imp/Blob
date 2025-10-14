# Blob — Interaction-Driven Web Vulnerability Scanner

**Blob** is an offensive web scanner focused on **real user interactions**. It fingerprints the target stack, **drives a headless browser** to click/type/scroll like a user, **captures real traffic** through a proxy, **injects context‑aware payloads** (filtered by stack and vector), **mutates** blocked payloads (WAF/ratelimit evasion), and **analyzes** responses (incl. OAST) to surface actionable findings.

```
URLs
  └─> Recon (stack) ──> Bot (Playwright) ──> Proxy (mitmproxy)
                        └─────────────────────────────────────> Injector ──> Analyzer ──> results/*.jsonl
                              (ZMQ: 5555→5556, heartbeats on 5557, status on 5558)
```

## Key Features

* **Hybrid Recon**: WhatWeb + Webanalyze + Wafw00f → normalized slugs mapped to available payloads (fallback to `generic`).
* **Realistic Exploration**: Playwright (Chromium) simulates rich interactions (menus/forms/modals/iframes/infinite scroll), injects XHR/Fetch hooks; User‑Agent rotation and cookie jar supported.
* **Passive Traffic Capture**: mitmproxy addon normalizes JSON/form/multipart/XML, prunes hop-by-hop headers, whitelists in‑scope hosts, and streams requests over ZMQ.
* **Stack‑Aware Injection**: vector filtering (params/headers/cookies/json/xml/multipart/GraphQL) + payload selection by detected stack + mutation on block + light WAF header bypasses; optional **OAST** via Interactsh.
* **Streaming Analysis**: baselines (per method/content‑type), heuristic detection (errors/sinks/session hints/GraphQL), OAST consumer, consolidated output to `results/results_filtered.jsonl`.
* **Orchestrated Pipeline**: `scanner.py` runs the flow, monitors heartbeats/status, gracefully shuts down ports (8080/5555/5556/5557), summarizes findings.

---

## Repository Layout (expected)

```
.
├── scanner.py
├── reco.py
├── bot.py
├── logscan.py
├── injector.py
├── analyzer.py
├── vector_filter.py
├── mutator.py
├── interactsh.py
├── urls.txt                 # one URL per line
├── useragents.txt           # one User-Agent per line
├── cookies/                 # optional, *.txt like: "name=value; name2=value2"
├── payloads/                # vector/engine/... e.g., sqli/mysql/*.txt, xss/generic/*.txt, etc.
└── results/                 # generated outputs
```

**Outputs**

* Recon: `reco/stack.json` (per‑URL stack slugs + `generic` fallback)
* Analysis: `results/results_filtered.jsonl` (interesting findings in streaming mode)

---

## Requirements

### System

* Python ≥ 3.10
* mitmproxy (provides `mitmdump`)
* WhatWeb, Webanalyze, Wafw00f (for reconnaissance)
* `lsof` (or alternative) for port cleanup

> Webanalyze requires its binary and technologies database; see its documentation for installation.

### Python

Install from `requirements.txt` (see separate file), then install Chromium for Playwright:

```bash
python -m playwright install chromium
```

---

## Quickstart

```bash
# 1) Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium

# 2) Inputs
echo "https://target.example" > urls.txt
echo "Mozilla/5.0 ..." > useragents.txt
# (Optional) place a cookie jar in ./cookies/ like: "name=value; other=foo"

# 3) Run
python scanner.py --urls urls.txt --payloads payloads --user-agents useragents.txt 

```

> The bot automatically loads the **first** `*.txt` file in `cookies/` and applies it to the start URL’s domain.
> The orchestrator currently launches the bot with `--depth 0` (see **Planned Patches**).

---

## Module-by-Module

* **`scanner.py`** — Orchestrates the full pipeline (recon → analyzer → injector → mitmdump + bot per URL), watches activity via heartbeats (5557) and injector status (5558), cleans up ports (8080/5555/5556/5557).
* **`reco.py`** — Runs WhatWeb/Webanalyze/Wafw00f, parses outputs, slugifies stacks, writes `reco/stack.json`. Includes `generic` if no engine‑specific payloads are mapped.
* **`bot.py`** — Playwright driver (Chromium headless), ignores HTTPS errors, rotates User‑Agents, auto‑loads a simple cookie jar, performs aggressive interactions (forms/buttons/menus/iframes/scroll), injects AJAX hooks. Options: `--start-url`, `--user-agents`, `--depth`, `--proxy`.
* **`logscan.py`** — mitmproxy addon: prunes hop‑by‑hop headers, robustly parses JSON/form/multipart/XML, restricts scope to hosts from `urls.txt`, streams to ZMQ **PUSH** (→ 5555).
* **`vector_filter.py`** — Skips static resources; infers injection context (param/header/cookie/json/xml/multipart/GraphQL) and returns **relevant vectors** for the injector.
* **`injector.py`** — Streaming mode: **PULL** (5555) real requests, select vectors via `vector_filter`, pick payloads by stack (`reco/stack.json` + `generic` fallback), send mutated/bypassed variants on blocks (403/406/429/503 or “access denied”), optional **OAST** (replace `OAST_DOMAIN`), **PUSH** to analyzer (5556), heartbeat PUB (5557), **STATUS REP** (5558).
* **`mutator.py`** — Families of mutations (encoding/obfuscation/polyglots) for XSS/SQLi/SSTI/XXE/LFI/NoSQL/LDAP, with limiters.
* **`analyzer.py`** — Baselines (LRU+TTL), heuristic detection (error traces, XSS sinks, state/session clues, GraphQL issues), **OAST** session consumer/poller, progressive write to `results/results_filtered.jsonl`.
* **`interactsh.py`** — Local client for Interactsh (keypair/session/register/poll/decrypt) used by injector (attach proofs) and analyzer (confirm callbacks).

---

## Current Limitations

* **Recon fidelity** depends on external CLIs; “exotic” stacks may fall back to `generic`.
* **Impact detection** is **heuristic**; results indicate likely issues, not guaranteed full exploitability.
* **Rate limiting/WAF**: basic mutation/backoff and light header tricks; no target‑aware pacing yet.
* **Auth flows**: no first‑class scripted logins (multi‑step/2FA). Cookie jar is supported.
* **GraphQL**: basic detection; no schema‑aware fuzzing yet.

---

## Planned Patches (short‑term)

Concrete, code‑level fixes we plan to ship next. **PRs welcome!**

1. **Depth Wiring in `scanner.py`**
   • *Problem*: Orchestrator hard‑codes `--depth 0` when invoking `bot.py`.
   • *Plan*: Add a `--depth` flag to `scanner.py` and **propagate** it to `bot.py`. Keep default `0`, allow user overrides.

2. **Auth‑Bypass Baselines Triggering**
   • *Problem*: `analyzer.py` expects `injection_point` labels like `GET param \`foo``/`POST form `bar``/`json `baz``, but `injector.py`emits`log-proxy param `foo``.
   • *Plan*: Harmonize labels **in injector** (preferred) or broaden analyzer regexes to recognize existing forms to **reactivate** auth‑bypass baselines.

3. **Stack Key Normalization**
   • *Problem*: `reco/stack.json` keys are full URLs (e.g., `https://site.tld`), while captured requests include paths/queries (e.g., `/login?x=1`). Strict lookups drop to `generic`.
   • *Plan*: Normalize to **scheme+host** (or same‑origin prefix match) before stack lookup in `injector.py`, preserving engine‑specific payload selection across paths.

4. **Unused Flags in `scanner.py`**
   • *Problem*: Flags like `--json-injection`, `--headers-injection`, `--latency-factor`, `--watch-status`, `--raw-results`, `--uninteresting-out` are exposed but unused in streaming mode.
   • *Plan*: Either **wire** relevant flags through to `injector.py`/`analyzer.py` (preferred for JSON/headers toggles & watch‑status) or **deprecate**/remove legacy ones from the CLI help.

> Once merged, we’ll cut a minor release and update the CLI docs.

---

## Contributing

We ❤️ contributions. If you value low‑noise, high‑signal scanning that mirrors real user behavior, you’ll feel at home.

* **Good first issues**: the four **Planned Patches** above.
* Style: clear commits, focused PRs, pragmatic tests (fixtures for sample requests/responses).
* Security: avoid high‑risk payloads by default; keep stack‑specific payloads in subfolders; document OAST usage explicitly.

---

## Legal

Blob is an **offensive security** tool. **Use only on systems you own or are explicitly authorized to test.** You are solely responsible for its use.

---

## Cheat Sheet

* **Run**: `python scanner.py --urls urls.txt --payloads payloads --user-agents useragents.txt`
* **Outputs**: `reco/stack.json`, `results/results_filtered.jsonl`
* **Ports**: mitmproxy 8080; ZMQ 5555 (log→inj), 5556 (inj→ana), 5557 (heartbeats), 5558 (status)
* **Depth**: currently fixed at `0` (see **Planned Patches**)
