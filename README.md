# 🛡️ Aegis360: Centralized Security Operations

A zero-trust, multi-layered control plane for adversarial prompt evaluation, LLM behavioral auditing, and localized threat telemetry.

Aegis360 bridges the gap between offensive AI red-teaming and defensive blue-team analytics by providing a highly structured sandbox to evaluate cognitive payloads before they hit production systems.

## 🏛️ System Architecture

The Aegis360 control plane is divided into four distinct operational modules:

- **👁️ CYclOPS (Cyber Operations Pipeline System):** The core 4-layer AI sandbox and zero-trust execution engine.
- **🐕 Cerberus (Threat Ingestion - _WIP_):** Multi-headed data scraper and threat intelligence feed parser.
- **🪽 Hermes (Cloud Operations - _WIP_):** Automated cloud synchronization and daily intelligence briefing generator.
- **🦉 Athena (Strategic Analytics - _WIP_):** Deep behavioral insights and long-term trend visualization.

---

## 👁️ The CYclOPS Engine (4-Layer Defense Pipeline)

CYclOPS acts as a localized combat arena for prompt injection and exploit validation, passing all payloads through a strict 4-layer pipeline:

1. **Layer 1: Semantic Intent Guardrail (`policy_engine.py`)**
   - Upgraded from brittle lexical arrays to a zero-temperature "LLM-as-a-Judge" semantic analyzer. Catches hostile intent (e.g., jailbreaks, system overrides) regardless of typographical variations.
2. **Layer 2: Isolated Execution (`pipeline_core.py`)**
   - Fires the payload into a live isolated LLM context window. Features an automatic **Simulation Fallback Mode** for offline testing without burning API tokens.
3. **Layer 3: Output Auditing (`policy_engine.py`)**
   - Intercepts the generated response before rendering to the UI. Scans for leaked system contexts, exposed cryptographic hashes, or unauthorized execution commands (e.g., `os.system`).
4. **Layer 4: Telemetry Oracle (`telemetry.py`)**
   - Acts as the system flight recorder. All payload inputs, execution results, and guardrail statuses are permanently logged to a local **DuckDB** instance for forensic review.

---

## 🚀 Installation & Setup

### 1. Environment Setup

Ensure you are running Python 3.10+ and install the required dependencies:

```bash
pip install streamlit requests duckdb
```
