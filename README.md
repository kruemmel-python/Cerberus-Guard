# Cerberus Guard AI

Cerberus Guard AI now runs as a backend-driven IDS/IPS stack with:

- real packet capture via `cap`/libpcap
- backend-side heuristics, LLM batching, caching and persistence
- SQLite storage for logs, traffic history and PCAP artifacts
- WebSocket updates for metrics, alerts, replay status and optional raw packets
- real OS firewall integration for block actions
- PCAP export plus historical replay mode
- a visual custom rule builder for pre-LLM decisions
- outbound webhook alerting from the backend service
- fleet mode with `standalone`, `hub` and `agent` deployment roles
- global block propagation across connected sensors
- privacy-preserving payload masking before cloud LLM prompts
- external threat intelligence feeds with backend refresh scheduling
- natural-language threat hunting over the SQLite forensics store
- advanced L7 protocol decoders for `HTTP`, `DNS`, `TLS`, `SSH`, `FTP`, `RDP`, `SMB` and `SQL`

Documentation:

- LM Studio usage guide: `USE.md`
- CAPE sandbox server setup: `CAPE_SETUP.md`
- Built-in local reverse-analysis sandbox: `Cerberus Lab` in `Settings -> Sandbox`
- Optional dynamic detonation via Windows Sandbox: enable `Windows Sandbox detonation` under `Cerberus Lab`
- Direct browser upload for downloaded files in `Dashboard -> Sandbox Analyses`, including local SHA-256 preview before submission
- Built-in structural analyzers for `PDF` and image formats, including malicious active-content indicators in exported sandbox PDF reports
- Built-in Office document analysis for `DOCX/XLSX/PPTX`, macro-enabled OOXML, legacy `DOC/XLS/PPT` and `RTF`

## Requirements

- Node.js 22+
- Windows: `Npcap` with WinPcap compatibility enabled
- Linux: `libpcap` plus either `ufw` or `iptables` for firewall enforcement

## Run locally

1. Install dependencies:
   `npm install`
2. Configure backend secrets as environment variables when needed:
   `GEMINI_API_KEY=...`
   `OPENAI_API_KEY=...`
   `ANTHROPIC_API_KEY=...`
   `OPENROUTER_API_KEY=...`
   `GROQ_API_KEY=...`
   `MISTRAL_API_KEY=...`
   `DEEPSEEK_API_KEY=...`
   `XAI_API_KEY=...`
3. Start frontend and backend together:
   `npm run dev`
4. Open the UI and configure:
   `Deployment Mode`: `standalone` for one node, `hub` for central management, `agent` to join a hub
   `Backend Base URL`: `http://localhost:8081`
   `Capture Interface`: your real network adapter
   `Capture Filter`: for example `ip and (tcp or udp)`
   `Payload Privacy Mode`: `Raw payload for local LLMs only` is recommended for LM Studio/Ollama; use `Strict masking` for cloud LLMs
   `Threat Intelligence`: enable feeds only after verifying outbound connectivity from the backend
5. Optional:
   Enable `OS firewall integration` only when the process has the required OS privileges.
   Enable `Live raw feed` only when you need decoded raw packets in the browser.
   Configure `Shared Fleet Token` plus `Hub URL` when this node should join or host a distributed sensor fleet.

## Backend API

- `GET /api/health`
- `GET /api/bootstrap`
- `GET /api/interfaces`
- `GET /api/config`
- `PUT /api/config`
- `GET /api/capture/status`
- `POST /api/capture/start`
- `POST /api/capture/stop`
- `POST /api/capture/replay`
- `GET /api/logs`
- `GET /api/traffic`
- `GET /api/metrics`
- `GET /api/pcap-artifacts`
- `GET /api/sandbox/analyses`
- `POST /api/sandbox/analyze-upload`
- `GET /api/sandbox/analyses/:analysisId/report.pdf`
- `GET /api/pcap-artifacts/:artifactId/download`
- `GET /api/fleet/sensors`
- `GET /api/threat-intel/status`
- `POST /api/threat-intel/refresh`
- `POST /api/forensics/chat`
- WebSocket stream: `ws://localhost:8081/traffic`
- Agent fleet WebSocket: `ws://localhost:8081/fleet/agent`

## Distributed mode

- `standalone`: local capture, analysis, storage and UI against one backend
- `hub`: central dashboard plus aggregation point for remote agents
- `agent`: capture and analyze locally, then forward logs, traffic, artifacts and metrics to a hub over WebSocket

To connect an agent to a hub:

1. Set the hub node to `Deployment Mode = hub`
2. Set the same `Shared Fleet Token` on hub and agent
3. On the agent, set `Deployment Mode = agent`
4. On the agent, set `Hub URL` to the hub backend, for example `http://10.0.0.5:8081`

## Threat intelligence

Cerberus Guard can load remote plain-text, Spamhaus DROP-style or JSON-array feeds into the backend and match IP/CIDR indicators before heuristics and LLM inspection. Feed refresh is configured in `Settings -> Threat Intelligence`.

## Threat hunting

The `Threat Hunt` tab sends a natural-language question to the backend. The backend generates read-only SQLite SQL, executes it against the forensics store and returns a summarized result plus the generated SQL.

## Sandbox integration

Cerberus Guard can submit suspicious local process files either to an external CAPE sandbox or to the built-in `Cerberus Lab` reverse-analysis pipeline from the backend. `Cerberus Lab` now supports an optional Windows-Sandbox-based dynamic execution stage in addition to static reverse analysis. You can also upload a downloaded file bundle directly from the browser in `Dashboard -> Sandbox Analyses`; the UI calculates a local SHA-256 preview for the primary sample before the backend performs the persisted analysis, and extra uploaded files are staged as sidecars for dynamic execution. For local process-path analyses, Cerberus Lab also auto-discovers adjacent DLL and manifest sidecars where possible. Stored sandbox results can also be exported as PDF reports directly from the UI. For the full CAPE server-side setup, reverse proxy guidance and token handling, see `CAPE_SETUP.md`.

Cerberus Lab now includes file-type-aware structural analyzers for `PDF` and common image formats. PDF samples are inspected for object graphs, streams, embedded JavaScript, embedded files, external URI actions, launch actions and auto-open behavior. Embedded `MZ` markers in PDFs are now validated against real PE structure before they are reported as embedded executables. Image samples are inspected for SVG active content, suspicious metadata, trailing appended payloads and embedded executable/archive signatures. When `Windows Sandbox detonation` is enabled, Cerberus Lab also opens `PDF` and supported image files in a guest viewer so dynamic analysis can capture spawned processes, network activity and filesystem changes for document/image-borne threats as well. The dynamic stage now distinguishes between plain viewer launch, attributed secondary execution in the viewer process tree, confirmed dropped payload files and classified remote TCP communication from viewer context vs. non-viewer child processes.

Cerberus Lab also analyzes Office-style documents. OOXML packages such as `DOCX/XLSX/PPTX` and macro-enabled `DOCM/XLSM/PPTM` are inspected for macro projects, auto-exec triggers, embedded objects, external relationships, ActiveX and custom UI content. Legacy OLE documents (`DOC/XLS/PPT`) and `RTF` samples are scanned for macro-like strings, embedded OLE objects, DDE fields and suspicious external references. These findings are included in the stored sandbox result, LLM review projection and exported sandbox PDF report.

When using a local LLM runtime such as LM Studio or Ollama, `Settings -> Sandbox -> Prioritize sandbox over traffic LLM` defers new traffic deep-inspection requests while Cerberus Lab is actively reviewing a file, so sandbox analyst summaries do not get starved behind normal traffic prompts.

## Supported LLM providers

- Gemini
- OpenAI
- Anthropic
- OpenRouter
- Groq
- Mistral
- DeepSeek
- xAI
- LM Studio
- Ollama

Default local endpoints:

- LM Studio: `http://localhost:1234/v1`
- Ollama: `http://localhost:11434`
