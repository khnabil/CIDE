#!/usr/bin/env python3
"""
CIDE Static Analysis Engine — OWASP Benchmark v1.2
Scans infrastructure source files for CWE-classified findings.
Outputs JSON findings for artifact synthesis.
"""

import os
import re
import json
import hashlib
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional

HELPERS_DIR = Path("target-repo/src/main/java/org/owasp/benchmark/helpers")
TESTCODE_DIR = Path("target-repo/src/main/java/org/owasp/benchmark/testcode")
REPORT_DIR   = Path("target-repo/src/main/java/org/owasp/benchmark/report")
SRC_ROOT     = Path("target-repo/src/main/java/org/owasp/benchmark")

@dataclass
class Finding:
    id: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cwe: str
    rule_id: str
    title: str
    file: str
    line: int
    col: int
    snippet: str
    remediation: str
    confidence: str        # HIGH / MEDIUM / LOW

findings: List[Finding] = []
_id_counter = [0]

def new_finding(severity, cwe, rule_id, title, file, line, col, snippet, remediation, confidence="HIGH"):
    _id_counter[0] += 1
    findings.append(Finding(
        id=f"SA-{_id_counter[0]:04d}",
        severity=severity,
        cwe=cwe,
        rule_id=rule_id,
        title=title,
        file=str(file),
        line=line,
        col=col,
        snippet=snippet.strip()[:120],
        remediation=remediation,
        confidence=confidence,
    ))

def read_lines(path):
    try:
        return open(path, encoding="utf-8", errors="replace").readlines()
    except Exception:
        return []

# ─────────────────────────────────────────────────────────────────────────────
# Rule R01 — Static shared JDBC Connection (CWE-362 / thread-safety)
# ─────────────────────────────────────────────────────────────────────────────
def rule_r01_static_connection():
    target = HELPERS_DIR / "DatabaseHelper.java"
    lines = read_lines(target)
    for i, line in enumerate(lines, 1):
        if re.search(r'private\s+static\s+Connection\s+\w+', line):
            new_finding(
                severity="CRITICAL",
                cwe="CWE-362",
                rule_id="R01",
                title="Static shared java.sql.Connection — concurrent access causes transaction interleaving",
                file=target,
                line=i, col=line.index("static"),
                snippet=line,
                remediation="Replace with DataSource.getConnection() in try-with-resources per request.",
            )

# ─────────────────────────────────────────────────────────────────────────────
# Rule R02 — Hardcoded credentials / secrets (CWE-798)
# ─────────────────────────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|secret|apikey|keystorepass)\s*=\s*["\'][^"\']{4,}["\']'), "CWE-798"),
    (re.compile(r'(?i)SONAR_PASSWORD\s*=\s*"[^"]+"'), "CWE-798"),
    (re.compile(r'keystorePass\s*=\s*["\'][^"\']+["\']'), "CWE-321"),
]

def rule_r02_hardcoded_secrets():
    scan_dirs = [HELPERS_DIR, REPORT_DIR]
    for d in scan_dirs:
        if not d.exists():
            continue
        for f in d.rglob("*.java"):
            lines = read_lines(f)
            for i, line in enumerate(lines, 1):
                for pat, cwe in SECRET_PATTERNS:
                    if pat.search(line) and "//" not in line[:line.find("=") if "=" in line else 0]:
                        new_finding(
                            severity="CRITICAL",
                            cwe=cwe,
                            rule_id="R02",
                            title=f"Hardcoded credential/secret in {f.name}",
                            file=f,
                            line=i, col=0,
                            snippet=line,
                            remediation="Externalize secrets to environment variables or a secrets manager.",
                        )
                        break
    # Also scan pom.xml for hardcoded keystorePass
    pom = Path("target-repo/pom.xml")
    pom_lines = read_lines(pom)
    seen_pom_secret = False
    for i, line in enumerate(pom_lines, 1):
        if re.search(r'keystorePass.*changeit|changeit.*keystorePass', line) and not seen_pom_secret:
            seen_pom_secret = True
            new_finding(
                severity="CRITICAL",
                cwe="CWE-321",
                rule_id="R02b",
                title="pom.xml hardcodes keystorePass=changeit in Cargo deployment config (5 profiles)",
                file=pom,
                line=i, col=0,
                snippet=line.strip(),
                remediation="Use Maven property with env-var source: ${env.KEYSTORE_PASS}",
            )

# ─────────────────────────────────────────────────────────────────────────────
# Rule R03 — Weak / prohibited TLS versions (CWE-326)
# ─────────────────────────────────────────────────────────────────────────────
def rule_r03_weak_tls():
    target = HELPERS_DIR / "Utils.java"
    lines = read_lines(target)
    for i, line in enumerate(lines, 1):
        if re.search(r'"TLSv1"', line) and not re.search(r'TLSv1\.[23]', line):
            new_finding(
                severity="HIGH",
                cwe="CWE-326",
                rule_id="R03",
                title="SSLContext constrained to TLSv1 only — prohibited by RFC 8996",
                file=target,
                line=i, col=line.find('"TLSv1"'),
                snippet=line,
                remediation='Replace with new String[]{"TLSv1.2","TLSv1.3"}.',
            )
        if re.search(r'NoopHostnameVerifier', line):
            new_finding(
                severity="HIGH",
                cwe="CWE-297",
                rule_id="R03b",
                title="NoopHostnameVerifier disables certificate hostname validation — MITM risk",
                file=target,
                line=i, col=line.find("NoopHostnameVerifier"),
                snippet=line,
                remediation="Use DefaultHostnameVerifier or SSLConnectionSocketFactory default.",
            )

# ─────────────────────────────────────────────────────────────────────────────
# Rule R04 — Exception swallowing without re-throw (CWE-390)
# ─────────────────────────────────────────────────────────────────────────────
def rule_r04_exception_swallow():
    scan_dirs = [HELPERS_DIR]
    for d in scan_dirs:
        if not d.exists():
            continue
        for f in d.rglob("*.java"):
            lines = read_lines(f)
            in_catch = False
            catch_start = 0
            brace_depth = 0
            catch_body_lines = []
            for i, line in enumerate(lines, 1):
                if re.search(r'}\s*catch\s*\(', line) or re.search(r'catch\s*\(', line):
                    in_catch = True
                    catch_start = i
                    brace_depth = 0
                    catch_body_lines = []
                if in_catch:
                    catch_body_lines.append(line)
                    brace_depth += line.count("{") - line.count("}")
                    if brace_depth < 0:
                        # End of catch block — analyse body
                        body = " ".join(catch_body_lines)
                        has_throw   = bool(re.search(r'\bthrow\b', body))
                        has_log     = bool(re.search(r'\b(log\.|logger\.|Logger\.|System\.err)', body))
                        has_println = bool(re.search(r'System\.out\.print', body))
                        is_empty    = not re.search(r'\w+', body.replace("catch","").replace("{","").replace("}","").strip())
                        if is_empty:
                            new_finding(
                                severity="MEDIUM",
                                cwe="CWE-390",
                                rule_id="R04",
                                title=f"Empty catch block in {f.name} — silently swallows exception",
                                file=f,
                                line=catch_start, col=0,
                                snippet=catch_body_lines[0] if catch_body_lines else "",
                                remediation="Log and/or rethrow; do not suppress exceptions silently.",
                                confidence="MEDIUM",
                            )
                        elif has_println and not has_throw and not has_log:
                            new_finding(
                                severity="MEDIUM",
                                cwe="CWE-390",
                                rule_id="R04b",
                                title=f"Exception caught, System.out only, not rethrown in {f.name}",
                                file=f,
                                line=catch_start, col=0,
                                snippet=catch_body_lines[0] if catch_body_lines else "",
                                remediation="Use a proper logger (SLF4J/Log4j2) and propagate or wrap exception.",
                                confidence="HIGH",
                            )
                        in_catch = False
                        catch_body_lines = []

# ─────────────────────────────────────────────────────────────────────────────
# Rule R05 — SQL error exposure to HTTP clients (CWE-209)
# ─────────────────────────────────────────────────────────────────────────────
def rule_r05_sql_error_exposure():
    target = HELPERS_DIR / "DatabaseHelper.java"
    src = "".join(read_lines(target))
    lines = read_lines(target)
    # Declaration spans two lines: "hideSQLErrors =\n            false"
    if re.search(r'hideSQLErrors\s*=\s*\n?\s*false', src):
        for i, line in enumerate(lines, 1):
            if 'hideSQLErrors' in line:
                new_finding(
                    severity="MEDIUM",
                    cwe="CWE-209",
                    rule_id="R05",
                    title="hideSQLErrors=false — full SQLException stack traces sent to HTTP clients",
                    file=target,
                    line=i, col=0,
                    snippet=line.strip(),
                    remediation="Set hideSQLErrors=true; never expose internal SQL errors to end users.",
                )
                break

# ─────────────────────────────────────────────────────────────────────────────
# Rule R06 — Weak cryptographic algorithms in infrastructure (CWE-327/CWE-328)
# ─────────────────────────────────────────────────────────────────────────────
WEAK_CRYPTO = [
    (re.compile(r'"DES(?!/)', re.I),        "CWE-327", "DES cipher in infrastructure code — key length 56-bit, breakable"),
    (re.compile(r'"MD5"'),                   "CWE-328", "MD5 hash algorithm — collision-vulnerable, not suitable for security"),
    (re.compile(r'"SHA-?1"'),                "CWE-328", "SHA-1 hash algorithm — collision-vulnerable per NIST SP 800-131A"),
    (re.compile(r'ECB'),                     "CWE-327", "ECB cipher mode — deterministic, leaks block patterns"),
    (re.compile(r'"RC4"', re.I),             "CWE-327", "RC4 cipher — prohibited by RFC 7465"),
]

def rule_r06_weak_crypto():
    # Only scan helpers — test code is expected to use weak crypto by design
    for f in HELPERS_DIR.rglob("*.java"):
        lines = read_lines(f)
        for i, line in enumerate(lines, 1):
            if "//" in line and line.index("//") < (line.index('"') if '"' in line else 9999):
                continue  # line is a comment before the pattern
            for pat, cwe, title in WEAK_CRYPTO:
                if pat.search(line):
                    new_finding(
                        severity="MEDIUM",
                        cwe=cwe,
                        rule_id="R06",
                        title=f"Weak crypto in infrastructure: {title} ({f.name})",
                        file=f,
                        line=i, col=0,
                        snippet=line,
                        remediation="Use AES-256-GCM or AES-256-CCM; use SHA-256+ for hashing.",
                        confidence="MEDIUM",
                    )

# ─────────────────────────────────────────────────────────────────────────────
# Rule R07 — Keystore / certificate file committed to SCM (CWE-321)
# ─────────────────────────────────────────────────────────────────────────────
def rule_r07_keystore_in_scm():
    ks = Path("target-repo/.keystore")
    if ks.exists():
        size = ks.stat().st_size
        with open(ks, "rb") as fh:
            sha256 = hashlib.sha256(fh.read()).hexdigest()
        new_finding(
            severity="CRITICAL",
            cwe="CWE-321",
            rule_id="R07",
            title=f"Binary keystore file committed to SCM ({size} bytes, SHA-256: {sha256[:16]}…)",
            file=ks,
            line=1, col=0,
            snippet=f".keystore — size={size}, sha256={sha256[:32]}",
            remediation="Add .keystore to .gitignore; use CI-injected secrets or Let's Encrypt.",
        )

# ─────────────────────────────────────────────────────────────────────────────
# Rule R08 — Dead / unreachable code stubs (CWE-561)
# ─────────────────────────────────────────────────────────────────────────────
def rule_r08_dead_code():
    target = HELPERS_DIR / "ExpressionEvaluator.java"
    if not target.exists():
        return
    lines = read_lines(target)
    null_returns = [(i, l) for i, l in enumerate(lines, 1) if re.search(r'return\s+null\s*;', l)]
    if len(null_returns) >= 2:
        new_finding(
            severity="LOW",
            cwe="CWE-561",
            rule_id="R08",
            title="ExpressionEvaluator.java — all methods return null (dead code stub)",
            file=target,
            line=null_returns[0][0], col=0,
            snippet=null_returns[0][1],
            remediation="Remove or implement ExpressionEvaluator; dead stubs inflate bytecode.",
            confidence="HIGH",
        )

# ─────────────────────────────────────────────────────────────────────────────
# Rule R09 — JNDI pool capacity wasted (design smell, CWE-400 adjacent)
# ─────────────────────────────────────────────────────────────────────────────
def rule_r09_connection_pool_waste():
    target = HELPERS_DIR / "DatabaseHelper.java"
    lines = read_lines(target)
    static_conn_found = any(re.search(r'private\s+static\s+Connection', l) for l in lines)
    pool_cfg = Path("target-repo/src/config/local/server.xml")
    pool_lines = read_lines(pool_cfg)
    max_total_found = any(re.search(r'maxTotal\s*=\s*"?1[2-9]', l) for l in pool_lines)
    if static_conn_found and max_total_found:
        new_finding(
            severity="LOW",
            cwe="CWE-400",
            rule_id="R09",
            title="JNDI pool maxTotal=12 but DatabaseHelper caches exactly 1 static Connection — 11 slots wasted",
            file=target,
            line=1, col=0,
            snippet="private static Connection conn (DatabaseHelper) + maxTotal=12 (server.xml)",
            remediation="Checkout connection per-request from the pool; set maxTotal=1 until fixed.",
            confidence="MEDIUM",
        )

# ─────────────────────────────────────────────────────────────────────────────
# Rule R10 — Spring @RestController in benchmark helpers (design boundary violation)
# ─────────────────────────────────────────────────────────────────────────────
def rule_r10_rest_controller_in_helpers():
    target = HELPERS_DIR / "DataBaseServer.java"
    if not target.exists():
        return
    lines = read_lines(target)
    for i, line in enumerate(lines, 1):
        if re.search(r'@RestController', line):
            new_finding(
                severity="LOW",
                cwe="CWE-501",
                rule_id="R10",
                title="@RestController in helpers/DataBaseServer.java — exposes /getall endpoint outside test boundary",
                file=target,
                line=i, col=0,
                snippet=line,
                remediation="Move management endpoints behind an authenticated admin path; never expose benchmark DB via unauthenticated REST.",
                confidence="HIGH",
            )

# ─────────────────────────────────────────────────────────────────────────────
# Rule R11 — Scan testcode for taint source diversity
# ─────────────────────────────────────────────────────────────────────────────
TAINT_SOURCES = {
    "getParameter":         "HTTP query/form param",
    "getHeader":            "HTTP request header",
    "getCookies":           "HTTP cookie",
    "getQueryString":       "Raw query string",
    "getPathInfo":          "URL path segment",
    "getInputStream":       "Raw request body",
    "getenv":               "OS environment variable",
    "getProperty":          "JVM system property",
    "getTheValue":          "SeparateClassRequest (safe — returns literal 'bar')",
    "ThingFactory.getThing":"ThingInterface reflection",
}

def rule_r11_taint_source_census():
    counts = {k: 0 for k in TAINT_SOURCES}
    if not TESTCODE_DIR.exists():
        return counts
    for f in sorted(TESTCODE_DIR.glob("*.java"))[:200]:  # sample first 200
        src = "".join(read_lines(f))
        for key in counts:
            counts[key] += len(re.findall(re.escape(key.split(".")[-1]), src))
    return counts

# ─────────────────────────────────────────────────────────────────────────────
# Rule R12 — Spotbugs equivalent: resource never closed patterns
# ─────────────────────────────────────────────────────────────────────────────
def rule_r12_unclosed_resources():
    """Hunt for new XYZ(...) where XYZ is a Closeable but no try-with-resources."""
    closeable_types = re.compile(r'\bnew\s+(FileInputStream|FileOutputStream|FileReader|FileWriter|BufferedReader|PrintWriter|InputStreamReader|OutputStreamWriter|Socket|ServerSocket)\s*\(')
    try_with = re.compile(r'try\s*\(')
    for f in HELPERS_DIR.rglob("*.java"):
        lines = read_lines(f)
        in_try_resource = False
        for i, line in enumerate(lines, 1):
            if try_with.search(line):
                in_try_resource = True
            if in_try_resource and ")" in line:
                in_try_resource = False
            m = closeable_types.search(line)
            if m and not try_with.search(line):
                new_finding(
                    severity="LOW",
                    cwe="CWE-772",
                    rule_id="R12",
                    title=f"Potential resource leak: {m.group(1)} not in try-with-resources ({f.name}:{i})",
                    file=f,
                    line=i, col=m.start(),
                    snippet=line,
                    remediation="Wrap resource in try-with-resources to guarantee close() on all paths.",
                    confidence="LOW",
                )

# ─────────────────────────────────────────────────────────────────────────────
# Rule R13 — javax.* namespace usage (Jakarta EE migration blocker)
# ─────────────────────────────────────────────────────────────────────────────
def rule_r13_javax_namespace():
    javax_import = re.compile(r'^import\s+javax\.(servlet|xml|persistence|annotation)\.')
    counts: dict = {}
    for f in SRC_ROOT.rglob("*.java"):
        lines = read_lines(f)
        for i, line in enumerate(lines, 1):
            if javax_import.match(line.strip()):
                pkg = javax_import.match(line.strip()).group(1)
                counts[pkg] = counts.get(pkg, 0) + 1
    return counts

# ─────────────────────────────────────────────────────────────────────────────
# Execute all rules
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Running CIDE static analysis rules…")

    rule_r01_static_connection()
    rule_r02_hardcoded_secrets()
    rule_r03_weak_tls()
    rule_r04_exception_swallow()
    rule_r05_sql_error_exposure()
    rule_r06_weak_crypto()
    rule_r07_keystore_in_scm()
    rule_r08_dead_code()
    rule_r09_connection_pool_waste()
    rule_r10_rest_controller_in_helpers()
    rule_r12_unclosed_resources()

    taint_counts = rule_r11_taint_source_census()
    javax_counts = rule_r13_javax_namespace()

    # Severity summary
    from collections import Counter
    sev_count = Counter(f.severity for f in findings)
    cwe_count = Counter(f.cwe for f in findings)

    result = {
        "tool": "CIDE Static Analysis Engine",
        "version": "1.0.0",
        "target": "org.owasp:benchmark:1.2",
        "java_source": "target-repo/src/main/java",
        "total_findings": len(findings),
        "severity_summary": dict(sev_count),
        "cwe_summary": dict(cwe_count),
        "taint_source_census_sample200": taint_counts,
        "javax_namespace_import_counts": javax_counts,
        "findings": [asdict(f) for f in findings],
    }

    out = Path("output/static_analysis_results.json")
    out.write_text(json.dumps(result, indent=2))
    print(f"\n{'='*60}")
    print(f"Total findings: {len(findings)}")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        n = sev_count.get(sev, 0)
        if n:
            print(f"  {sev:8s}: {n}")
    print(f"\njavax.* import counts: {javax_counts}")
    print(f"Taint source census (200-file sample): {taint_counts}")
    print(f"\nResults written to {out}")
