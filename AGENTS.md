# CIDE Autonomous Agent Operating Directives

- **Context Hygiene**: Retain only high-level topological summaries in the primary conversation stream. Delegate broad source code scans to `explore` subagents.
- **Intent Reconciliation**: Parse files in `@/docs/` and explicitly compare them against `@/target-repo/src/main/java`.
- **Output Standards**: Write complete, production-grade markdown and HTML artifacts into `@/output/` without conversational prefaces or placeholder text.
