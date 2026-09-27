# Cognitive and Intent Debt Eradicator (CIDE)

CIDE is an autonomous developer onboarding and maintenance workflow engine built inside the **IBM Bob 2.0 IDE**. It addresses the compounding developer friction caused by Technical, Cognitive, and Intent Debt across legacy applications.

## Key Features & Architecture
- **Isolated Subagent Orchestration**: Deploys parallel `explore` and `general` subagents to eliminate LLM context degradation and context rot.
- **Intent Recovery Engine**: Synthesizes unstructured legacy specification documents (`docs/`) with live source code to reconstruct lost Architectural Decision Records (ADRs).
- **Automated Governance**: Generates machine-readable SPDX 2.3 SBOMs and visual security dashboards evaluating licensing risks and Common Weakness Enumerations (CWEs).

## Repository Structure
- `.bob/`: Custom modes (`custom_modes.yaml`), MCP configurations (`mcp.json`), and agent configurations.
- `docs/`: Input legacy requirements and specifications.
- `output/`: Generated deliverables:
  - `ARCHITECTURE.md`
  - `SOFTWARE_ARCHITECTURE_REPORT.md`
  - `INTENT_ADR.md`
  - `sbom.spdx.json`
  - `SECURITY_AUDIT.html`
- `bob_sessions/`: Verifiable task session consumption summaries from IBM Bob IDE.

## Verification & Usage
1. Open the project in IBM Bob IDE.
2. Select the **🛡️ CIDE Orchestrator** mode.
3. Target legacy assets using context mentions (`@/target-repo` and `@/docs/`) to run automated audits.
