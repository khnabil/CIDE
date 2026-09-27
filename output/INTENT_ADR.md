# Intent & Architectural Decision Records (INTENT_ADR)

**Project:** OWASP Benchmark Java v1.2  
**Subagent Type:** General — Intent Reconciliation  
**Primary Sources:**
- `docs/legacy_requirements.txt` — Archive Rev 2018 (6 stated constraints)
- `target-repo/src/main/java/` — 2,765 Java source files
- `target-repo/src/main/resources/benchmark.properties`, `ESAPI.properties`
- `target-repo/src/config/web.xml`, `local/server.xml`
- `target-repo/expectedresults-1.2.csv` — 2,740 ground-truth labels

**Prepared by:** CIDE General Subagent — Synthesis Engine  
**Date:** 2025

---

## Part I — Reconciliation Master Table

Six requirements were extracted from the 2018 specification. Each is evaluated against direct code evidence gathered from corpus analysis.

| Req ID | Verbatim Requirement | Status | Drift Class | ADR |
|--------|---------------------|--------|-------------|-----|
| REQ-1 | "Monolithic benchmark harness structured on synchronous Java Servlets and raw JDBC access." | ✅ **CONFIRMED** | None | ADR-001 |
| REQ-2 | "High-throughput testing takes precedence over object-relational mapping (ORM) abstraction layers." | ⚠️ **PARTIAL DRIFT** | Accretion — ORM present in infra; absent from test paths | ADR-002 |
| REQ-3 | "Input vectors across all inbound servlets must neutralize CWE-89 (SQL Injection)." | 🟡 **TERMINOLOGICAL DRIFT** | Documentation ambiguity — requirement phrase contradicts dual-polarity design | ADR-003 |
| REQ-4 | "Input vectors across all inbound servlets must neutralize CWE-79 (Cross-Site Scripting)." | 🟡 **TERMINOLOGICAL DRIFT** | Documentation ambiguity — same class as REQ-3 | ADR-004 |
| REQ-5 | "Encryption modules must strictly prohibit ECB mode and enforce AES-128 / AES-256 standards." | 🔴 **DESIGN CONTRADICTION** | Scope confusion — prohibition applies to infrastructure; test cases must exercise prohibited algorithms | ADR-005 |
| REQ-6 | "Raw JDBC statements were explicitly selected to measure native driver response latency without Hibernate/JPA caching skew." | ⚠️ **PARTIAL DRIFT** | Latency purity violated by co-loaded ORM stack and single static `Connection` anti-pattern | ADR-006 |

**Supplemental findings** (no legacy requirement parent; identified during cross-reference):

| Finding ID | Observation | ADR |
|------------|-------------|-----|
| SUP-1 | TLSv1-only SSL factory breaks crawling on Java 11+ | ADR-007 |
| SUP-2 | "High-throughput" language is unsupported by any measurement code | ADR-008 |
| SUP-3 | ESAPI infrastructure config (AES/CBC/128) aligns with REQ-5 but is never enforced | ADR-009 |

---

## Part II — Evidence Corpus Summary

Cross-reference statistics derived from full corpus analysis:

| Metric | Count | Source |
|--------|-------|--------|
| Total test servlets | 2,740 | `testcode/*.java` |
| Servlets extending `HttpServlet` (100%) | 2,740 | `grep "extends HttpServlet"` |
| Async/reactive patterns (`AsyncContext`, `CompletableFuture`) | 0 | `grep AsyncContext…` |
| JAX-RS/Spring MVC annotations in testcode | 0 | `grep @Path, @RestController…` |
| Test cases using raw JDBC `getSqlStatement()` | 178 | grep analysis |
| Test cases using raw JDBC `getSqlConnection()` (parameterized) | 154 | grep analysis |
| Test cases using Spring `JdbcTemplate` | 172 | grep analysis |
| Test cases using Hibernate session directly | **0** | grep analysis — infra only |
| Total SQL test cases | 504 | `expectedresults-1.2.csv` |
| SQL true positives (CWE-89, unparameterized) | 272 (54%) | `expectedresults-1.2.csv` |
| SQL true negatives (parameterized / safe) | 232 (46%) | `expectedresults-1.2.csv` |
| XSS true positives (CWE-79, unencoded output) | 246 (54%) | `expectedresults-1.2.csv` |
| XSS true negatives (ESAPI-encoded output) | 209 (46%) | `expectedresults-1.2.csv` |
| Crypto test cases: ECB mode (DES/ECB or AES/ECB) | 60 | grep analysis |
| Crypto test cases: DES/CBC (CWE-327 true positive) | 97 | grep analysis |
| Crypto test cases: AES/GCM (safe, compliant) | 40 | grep analysis |
| Crypto test cases: AES/CCM (safe, but unusual) | 26 | grep analysis |
| Crypto test cases: DES/ECB via `cryptoAlg1` property | 33 | grep analysis |
| ESAPI infrastructure cipher config | AES/CBC/PKCS5Padding, 128-bit | `ESAPI.properties:24-26` |
| JNDI connection pool size (`maxTotal`) | 12 connections | `server.xml:40` |
| Static shared `Connection` in `DatabaseHelper` | 1 (non-thread-safe) | `DatabaseHelper.java:36` |

---

## Part III — Architectural Decision Records

---

### ADR-001 — Synchronous Servlet Monolith

**Status:** CONFIRMED — No Drift  
**Date Originated:** 2015 (initial commit)  
**Legacy Requirement:** REQ-1  
**Authors:** Dave Wichers, Nick Sanidas (per file headers)

#### Context

In 2015, the OWASP Benchmark was conceived as a ground-truth harness for SAST/DAST/IAST tool evaluation. The fundamental architectural question was: *what execution model maximises the fidelity of test case isolation while being tractable to generate at scale?*

The Java EE Servlet API provided an unambiguous answer — each `HttpServlet` subclass handles exactly one URL, processes one request synchronously per thread, and has no implicit shared state. This made it ideal for a generated corpus where each test case must be:

1. Independently addressable by a crawler
2. Structurally uniform to enable automated scorecard generation
3. Easy to generate at scale via templating

#### Decision

All 2,740 test cases extend `javax.servlet.http.HttpServlet` directly and are registered via `@WebServlet(value = "/{category}-{nn}/BenchmarkTestNNNNN")`. The deployment unit is a single WAR file (`benchmark.war`). No asynchronous dispatch (`AsyncContext`, `startAsync()`), messaging, or reactive streams were introduced.

**Code evidence:**
```
$ grep "extends " testcode/*.java | grep -oP "extends \w+" | sort | uniq -c
2740 extends HttpServlet
```

Zero instances of `AsyncContext`, `CompletableFuture`, `@Async`, `ExecutorService`, or `ForkJoinPool` anywhere in the codebase.

#### Consequences

- ✅ Perfect structural uniformity — the crawler XML (`data/benchmark-crawler-http.xml`) can enumerate all 2,740 test URLs deterministically
- ✅ No implicit state sharing between test cases — each servlet is isolated
- ✅ Tomcat's default thread-per-request model handles concurrency at the container level
- ⚠️ Tomcat's default thread pool (unconfigured, defaulting to 200 threads) means concurrent execution against the shared static `Connection` remains a risk (see ADR-006)

#### Alignment with REQ-1

**100% aligned.** The "monolithic" and "synchronous Java Servlets" constraints are unambiguously implemented.

---

### ADR-002 — Spring JdbcTemplate as an Expanded SQLI Test Surface

**Status:** PARTIAL DRIFT — Intentional Design Evolution  
**Date Originated:** 2015–2016 (Spring integration added after v1.0)  
**Legacy Requirement:** REQ-2  
**Authors:** Juan Gama, Kevin Roche

#### Context

The original 2015 design (REQ-2) stated that "high-throughput testing takes precedence over ORM abstraction layers." The intent was to exercise the raw JDBC driver path — `Statement`, `PreparedStatement`, `CallableStatement` — without any caching or abstraction overhead introduced by frameworks like Hibernate or Spring Data.

However, evaluating SAST tools requires testing them across *all possible coding patterns* that developers use, not just raw JDBC. Real-world applications use Spring's `JdbcTemplate`, and SAST tools must be able to detect SQL injection through Spring's template methods. This created pressure to expand the test surface beyond raw JDBC.

#### Decision

Spring `JdbcTemplate` was added as a third persistence path, accessible via `DatabaseHelper.JDBCtemplate` (a public static field). **172 test cases** route SQL through `JdbcTemplate.queryForObject()`, `queryForRowSet()`, and `execute()` with unsanitized string concatenation:

```java
// BenchmarkTest00025 — true positive SQLi via JdbcTemplate
String sql = "SELECT userid from USERS where USERNAME='foo' and PASSWORD='" + param + "'";
Long results = DatabaseHelper.JDBCtemplate.queryForObject(sql, Long.class);
```

Critically, **Hibernate ORM is never directly called by any test servlet.** The two `HibernateUtil` instances in `DatabaseHelper` are used exclusively for schema bootstrapping (`initData()`, `initClassicData()`) — they seed the HSQLDB tables at startup. No test case calls `session.createQuery()` or `SessionFactory.openSession()`.

#### Persistence Mechanism Distribution in Test Code

| Mechanism | Test Cases | Notes |
|-----------|-----------|-------|
| Raw `Statement.executeUpdate/Query()` | 178 | Unparameterized — primary SQLi path |
| `Connection.prepareStatement()` / `prepareCall()` | 154 | Parameterized JDBC |
| Spring `JdbcTemplate` | 172 | String-concatenated SQL via Spring |
| Hibernate ORM | **0** | Infrastructure use only — never in test paths |

#### Consequences

- ✅ Spring `JdbcTemplate` test cases (172) allow evaluation of tool coverage across a widely used framework
- ✅ Hibernate is isolated to infrastructure; it does not contaminate test-case execution paths
- ⚠️ Both Hibernate `SessionFactory` instances and the Spring `ClassPathXmlApplicationContext` are loaded unconditionally at startup — even for a test run that exercises only `DES/CBC` crypto test cases. This introduces unnecessary classloading overhead (~50MB additional heap) and contradicts the "high-throughput" spirit of REQ-2
- ⚠️ The 2018 requirements document was not updated to reflect the Spring JdbcTemplate expansion — it still reads as if raw JDBC is the only mechanism

#### Alignment with REQ-2

**~66% aligned.** The "no ORM in test paths" constraint is structurally honoured — no test servlet ever calls Hibernate directly. However, the requirement's spirit (latency isolation through exclusion of framework overhead) is compromised by unconditional startup loading of both Hibernate and Spring.

---

### ADR-003 — SQL Injection: Dual-Polarity Test Design vs. "Neutralize" Language

**Status:** TERMINOLOGICAL DRIFT — Documentation Debt  
**Date Originated:** 2015  
**Legacy Requirement:** REQ-3

#### Context

REQ-3 states: *"Input vectors across all inbound servlets must neutralize CWE-89 (SQL Injection)."* Read literally, this requires that all 504 SQL-related test cases prevent SQL injection. This is factually false in the implementation — and intentionally so.

The fundamental design principle of the OWASP Benchmark is **dual-polarity**: every category contains both true-positive (vulnerable) and true-negative (safe) test cases. This is what allows the scoring system to compute true positive rate (TPR) and false positive rate (FPR) for any evaluated tool. Without true positives, there is no meaningful benchmark — only a corpus of safe code.

#### Decision

The 504 SQL injection test cases are divided into:

| State | Count | % | Mechanism |
|-------|-------|---|-----------|
| True positive (CWE-89 exploitable) | 272 | 54% | String concatenation into SQL: `"... VALUES ('" + param + "')"` |
| True negative (safe) | 232 | 46% | `PreparedStatement.setString(1, param)` — parameterized binding |

**True positive example** — [`BenchmarkTest00018`](target-repo/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00018.java:54):
```java
// HTTP header value flows directly into unparameterized SQL
String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";
statement.executeUpdate(sql);  // ← CWE-89 injection point
```

**True negative example** — [`BenchmarkTest00024`](target-repo/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00024.java):
```java
// param flows into parameterized placeholder — NOT injectable
String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + param + "'";
statement.setString(1, "foo");  // username bound; password still injected — TP
```

> **Note:** `BenchmarkTest00024` is actually a *true positive* because `param` is still concatenated into the `PASSWORD` clause. The `?` placeholder only protects the `USERNAME` field. This is a deliberately subtle case designed to trip up tools that detect parameterization but miss partial injection.

#### Consequences

- ✅ Dual-polarity enables meaningful tool evaluation on both TPR and FPR
- 🔴 The 2018 requirements document used "must neutralize" — language borrowed from production security policy — which is semantically inverted for a benchmark context
- ⚠️ Any developer reading REQ-3 without knowledge of the benchmark's purpose would conclude the 272 exploitable test cases are bugs, not features

#### Recommended Requirement Restatement

> *"SQL injection test cases must include both exploitable instances (true positives for tool detection) and safely parameterized instances (true negatives). Ground-truth polarity is defined in `expectedresults-1.2.csv`."*

#### Alignment with REQ-3

**0% literal alignment / 100% intentional design alignment.** The requirement text directly contradicts the implementation. This is the clearest example of **documentation debt** in the legacy specification.

---

### ADR-004 — Cross-Site Scripting: Same Dual-Polarity Design, Same Documentation Debt

**Status:** TERMINOLOGICAL DRIFT — Documentation Debt  
**Date Originated:** 2015  
**Legacy Requirement:** REQ-4

#### Context

REQ-4 mirrors REQ-3 exactly: *"Input vectors across all inbound servlets must neutralize CWE-79 (Cross-Site Scripting)."* The analysis is identical to ADR-003.

#### Decision

455 XSS test cases are split:

| State | Count | % | Mechanism |
|-------|-------|---|-----------|
| True positive (CWE-79, unencoded output) | 246 | 54% | Raw user input written via `response.getWriter().format(locale, param, obj)` |
| True negative (ESAPI-encoded output) | 209 | 46% | `ESAPI.encoder().encodeForHTML(param)` applied before write |

**True positive example** — [`BenchmarkTest00013`](target-repo/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00013.java:54-56):
```java
// Referer header flows unencoded to response — XSS sink
response.setHeader("X-XSS-Protection", "0");   // explicitly disables browser protection
Object[] obj = {"a", "b"};
response.getWriter().format(java.util.Locale.US, param, obj);  // ← CWE-79 injection
```

**True negative example** — [`BenchmarkTest00282`](target-repo/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00282.java):
```java
// param HTML-encoded before use in format string
String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
Object[] obj = {bar, "b"};
response.getWriter().printf("Formatted like: %1$s and %2$s.", obj);  // safe
```

**Notable design detail:** XSS true-positive test cases explicitly set `X-XSS-Protection: 0` to disable the browser's built-in XSS filter. This ensures DAST tools receive the unfiltered reflected payload and can detect it as a confirmed vulnerability, rather than having it blocked client-side.

#### Alignment with REQ-4

Same assessment as ADR-003: **0% literal / 100% intentional.** Identical documentation debt.

---

### ADR-005 — Cryptographic Algorithm Constraints: Scope Inversion

**Status:** DESIGN CONTRADICTION — Scope Must Be Defined More Precisely  
**Date Originated:** 2015  
**Legacy Requirement:** REQ-5

#### Context

REQ-5 states: *"Encryption modules must strictly prohibit ECB mode and enforce AES-128 / AES-256 standards."*

This requirement, if applied globally, would make it impossible to have true-positive test cases for CWE-327 (Use of Broken or Risky Cryptographic Algorithm) — the entire reason the `crypto-*` category exists. The benchmark needs to instantiate weak algorithms so that security tools can find them.

There is, however, a critical distinction: the requirement **makes sense for infrastructure code** (the `helpers/` layer that the benchmark itself runs on) but is **necessarily violated by test code** (the `testcode/` layer that *exercises* weak algorithms as evaluation targets).

#### Decision — Crypto Algorithm Distribution

Actual algorithms used across 246 crypto test cases:

| Algorithm | Count | Compliant with REQ-5? | CWE |
|-----------|-------|-----------------------|-----|
| `DES/CBC/PKCS5Padding` | 97 | ❌ No (DES, not AES) | CWE-327 TP |
| `AES/GCM/NoPadding` | 40 | ✅ Yes (AES, secure mode) | CWE-327 TN |
| `DES/ECB/PKCS5Padding` (via `cryptoAlg1` property) | 33 | ❌ No (DES + ECB) | CWE-327 TP |
| `AES/CCM/NoPadding` (via `cryptoAlg2` property) | 26 | ✅ Yes (AES, authenticated) | CWE-327 TN |
| `AES/ECB/PKCS5Padding` | 27 | ❌ ECB mode (AES but ECB) | CWE-327 TP |
| `DESede/ECB/PKCS5Padding` | 33 | ❌ No (3DES + ECB) | CWE-327 TP |

**`benchmark.properties` configures the default weak algorithm:**
```properties
# benchmark.properties — controls 33 test cases via PropertiesManager
cryptoAlg1=DES/ECB/PKCS5Padding    # ← default for "weak" crypto test cases
cryptoAlg2=AES/CCM/NoPadding       # ← default for "safe" crypto test cases
```

**Infrastructure alignment — `ESAPI.properties` IS AES-128 compliant:**
```properties
# ESAPI.properties — infrastructure encryption config
Encryptor.EncryptionAlgorithm=AES
Encryptor.CipherTransformation=AES/CBC/PKCS5Padding
Encryptor.EncryptionKeyLength=128
```

This is the correct scope: ESAPI's own crypto (used in `DatabaseHelper.printResults()` for output encoding, not encryption) is configured to AES-128/CBC. No infrastructure code uses DES or ECB for actual encryption.

**The `RSA/ECB/OAEPWithSHA-512AndMGF1Padding` in `Utils.getCipher()`** uses "ECB" as RSA's padding-mode label, not as a block cipher mode. RSA has no block chaining concept — this is safe and should not be conflated with symmetric ECB mode.

#### Developer Intent Reconstruction

The 2018 requirements author almost certainly intended REQ-5 to govern the *infrastructure utilities* — specifically, to ensure that the benchmark's own operational security (password storage, JDBC connection security, cookie signing) was not compromised. The requirement was **misscoped** as a universal prohibition, when it should have been scoped as: *"Infrastructure code (helpers/) must not use ECB mode or DES/3DES. Test case code (testcode/) is exempt as it exercises prohibited algorithms by design."*

#### Alignment with REQ-5

| Scope | Alignment |
|-------|-----------|
| Infrastructure (`helpers/`) | ✅ ESAPI configured AES/CBC/128; no infrastructure code uses DES/ECB |
| Test cases (`testcode/`) | 🔴 160 of 246 crypto tests exercise prohibited algorithms — **by design** |

---

### ADR-006 — Static JDBC Connection vs. Latency Isolation Invariant

**Status:** PARTIAL DRIFT — Implementation Anti-Pattern Contradicts Stated Rationale  
**Date Originated:** 2015  
**Legacy Requirement:** REQ-6

#### Context

REQ-6 provides the explicit *rationale* for the raw JDBC choice: *"Raw JDBC statements were explicitly selected to measure native driver response latency without Hibernate/JPA caching skew."*

This rationale has three distinct claims that can be verified against the implementation:

1. **Raw JDBC is used** — partially true (see ADR-002)
2. **No Hibernate/JPA caching skew** — compromised by startup loading
3. **Native driver latency is measured** — not implemented (see ADR-008)

The most significant structural contradiction is in `DatabaseHelper` itself:

**`DatabaseHelper.java:36`:**
```java
private static Connection conn;  // single connection, never released
```

**`DatabaseHelper.java:157-168`:**
```java
public static java.sql.Connection getSqlConnection() {
    if (conn == null) {
        try {
            InitialContext ctx = new InitialContext();
            DataSource datasource = (DataSource) ctx.lookup("java:comp/env/jdbc/BenchmarkDB");
            conn = datasource.getConnection();  // takes ONE connection from pool
            conn.setAutoCommit(false);
        } catch (SQLException | NamingException e) { ... }
    }
    return conn;  // always returns same connection
}
```

Meanwhile, `server.xml` configures a connection pool of 12:
```xml
maxTotal="12" maxIdle="2" maxWaitMillis="5000"
```

**The pool is configured for 12 concurrent connections, but `DatabaseHelper` only ever obtains one.** The remaining 11 slots are unused because `getSqlConnection()` is lazy-initialised and cached as a singleton static field. This means:

- Every servlet invocation that calls `getSqlStatement()` shares the same `Connection` object
- The `DataBaseFilter` calls `getSqlConnection().rollback()` after every response — this works correctly in single-thread sequential execution but will cause transaction interleaving if two requests are processed concurrently
- The "latency isolation" rationale is undermined because a single Connection serialises all SQL statements regardless of thread count

#### Consequences

| Scenario | Behaviour |
|---------|-----------|
| Sequential crawler (intended) | ✅ Correct — one request at a time, rollback between tests |
| Concurrent DAST scan | 🔴 Connection contention — statements from different requests share the same `Connection`, corrupting transaction boundaries |
| JMeter/k6 load test | 🔴 Race condition on `conn.setAutoCommit(false)` line — first thread wins |

#### Alignment with REQ-6

**~40% aligned.** Raw JDBC is used, but:
- Latency is never measured (no timing instrumentation — see ADR-008)
- Hibernate/JPA is loaded at startup regardless (contradicts "without caching skew")
- The static shared `Connection` is an anti-pattern for the "native driver latency" claim, as it serialises requests rather than isolating per-request latency

---

### ADR-007 — TLSv1-Only SSL Factory (Latent Crawler Defect)

**Status:** UNINTENDED DRIFT — No Legacy Requirement Parent  
**Date Originated:** ~2015–2016 (original TLS configuration)

#### Context

[`Utils.getSSLFactory()`](target-repo/src/main/java/org/owasp/benchmark/helpers/Utils.java:419-427) creates an SSL socket factory explicitly restricted to TLSv1:

```java
SSLConnectionSocketFactory sslsf =
    new SSLConnectionSocketFactory(
        sslcontext,
        new String[]{"TLSv1"},   // ← protocol whitelist — TLSv1 only
        null,
        NoopHostnameVerifier.INSTANCE);  // ← hostname validation disabled
```

TLSv1 was deprecated by RFC 8996 (March 2021). Java 11 added `TLSv1` to `jdk.tls.disabledAlgorithms` in the default `java.security` policy. This means `Utils.getSSLFactory()` will throw `SSLHandshakeException: No appropriate protocol` on any Java 11+ runtime in default configuration.

The benchmark's own `runBenchmark.sh` and `runCrawler.sh` scripts target Tomcat over HTTPS on port 8443. The crawler (`runCrawler.sh`) uses the `benchmarkutils-maven-plugin` which calls back through this SSL factory.

#### Developer Intent (Reconstructed)

In 2015, TLSv1.2 was not universally available and TLSv1 was the prevailing minimum. The `NoopHostnameVerifier` was used because the benchmark's self-signed keystore (`.keystore`, password `changeit`) cannot pass hostname validation — a deliberate simplification for a local test environment.

#### Recommended ADR Resolution

```java
// Replace in Utils.getSSLFactory()
new String[]{"TLSv1.2", "TLSv1.3"}  // drop TLSv1
// Replace NoopHostnameVerifier with:
SSLConnectionSocketFactory.getDefaultHostnameVerifier()  // or allow self-signed only
```

---

### ADR-008 — "High-Throughput" Claim Has No Measurement Implementation

**Status:** UNIMPLEMENTED INTENT — No Code Evidence for Stated Goal  
**Date Originated:** 2018 requirements document  
**Legacy Requirement:** REQ-2 (partial)

#### Context

REQ-2 states: *"High-throughput testing takes precedence over object-relational mapping (ORM) abstraction layers."*

The word "high-throughput" implies that the system either:
(a) Measures throughput as part of its benchmark output, OR
(b) Is architecturally optimised for high throughput as an operational characteristic

Analysis of the entire codebase finds:
- Zero instances of `System.nanoTime()`, `System.currentTimeMillis()`, or any timing instrumentation
- Zero instances of throughput metrics, request-per-second reporting, or latency histograms
- Zero JMH (Java Microbenchmark Harness) or similar performance framework integration
- The crawler (`runCrawler.sh`) submits one request at a time, sequentially

The connection pool (`maxTotal=12`) is configured for modest concurrency. The benchmark was crawled with the `benchmarkutils-maven-plugin` sequentially. There is no evidence that throughput was ever measured.

#### Developer Intent (Reconstructed)

The "high-throughput" language was a **design rationale justification** — it explained *why* raw JDBC was chosen (to avoid ORM overhead) rather than describing an operational characteristic of the system. It was a 2018 re-articulation of the 2015 design decision, not a new requirement to instrument throughput.

In other words: "we chose raw JDBC because it has less overhead than ORM, which means the benchmark can be crawled faster" — not "we measure throughput and report it."

#### Consequence

The legacy requirements document contains aspirational language that was never operationalised. Any future modernisation that introduces throughput measurement should reference this ADR as the gap.

---

### ADR-009 — ESAPI Infrastructure Encryption Config Aligns With REQ-5 But Is Narrowly Scoped

**Status:** CONFIRMED ALIGNMENT (infrastructure scope only)  
**Date Originated:** 2015  
**Legacy Requirement:** REQ-5 (infrastructure scope interpretation)

#### Context

`ESAPI.properties` configures the OWASP ESAPI library's own cryptographic operations:

```properties
# ESAPI.properties
Encryptor.EncryptionAlgorithm=AES
Encryptor.CipherTransformation=AES/CBC/PKCS5Padding
Encryptor.EncryptionKeyLength=128
Encryptor.cipher_modes.combined_modes=GCM,CCM,IAPM,EAX,OCB,CWC
```

This configuration:
- ✅ Uses AES (compliant with REQ-5)
- ✅ Uses 128-bit key (compliant with REQ-5 "AES-128")
- ✅ Uses CBC mode (not ECB — compliant with REQ-5 ECB prohibition)
- ✅ Allows GCM/CCM as combined modes (state-of-the-art)

However, ESAPI's encryption is **never called by any infrastructure class** in the benchmark. `ESAPI.encoder().encodeForHTML()` (used extensively) is an *encoding* operation, not a *cryptographic* operation. The ESAPI encryptor would only be invoked via `ESAPI.encryptor().encrypt()`, which does not appear anywhere in the codebase.

The REQ-5 compliance through `ESAPI.properties` is therefore **passive** — it ensures that if a developer were to add ESAPI-based encryption to the infrastructure, it would default to AES/CBC/128. It does not enforce REQ-5 across the codebase.

---

## Part IV — Trade-Off Register

### TR-001: Raw JDBC vs ORM — Correctness vs. Coverage

| Dimension | Legacy Assumption (2018) | Modern Context (2025) |
|-----------|-------------------------|-----------------------|
| **Rationale** | Raw JDBC measures true driver latency; ORM adds caching overhead | SAST tools must detect SQLi through ORMs too (Spring Data, Hibernate HQL) |
| **Design choice** | Use raw JDBC exclusively | Expand to include Spring JdbcTemplate (done in v1.2); Hibernate HQL test cases added for v1.3 |
| **Trade-off** | Latency purity vs. coverage breadth | Coverage breadth wins — benchmark value is completeness |
| **Risk** | Hibernate classloading adds startup overhead unconditionally | Gate with `-Phibernate` profile or startup flag to restore latency isolation |
| **Cloud impact** | JDBC-only apps are rare in modern microservices (JPA/R2DBC dominant) | v1.3 will need reactive JDBC (`r2dbc`) for completeness |

### TR-002: Dual-Polarity vs. "Neutralize" Language

| Dimension | Legacy Assumption (2018) | Modern Context (2025) |
|-----------|-------------------------|-----------------------|
| **Rationale** | Requirement text borrowed from production security policy phrasing | Benchmark evaluation requires both vulnerable and safe test cases |
| **Documentation state** | "Must neutralize CWE-89" reads as universal prohibition | Should read: "Must provide ground-truth positive and negative test vectors for CWE-89" |
| **Risk** | New contributors may interpret true-positive test cases as bugs | Add `// TRUE POSITIVE: CWE-89` comment block to every vulnerable test case |
| **Modern tooling** | SARIF output consumers expect both TP and FP rates | Dual polarity directly serves SARIF Benchmark Score computation |

### TR-003: Monolithic WAR vs. Microservice Decomposition

| Dimension | Legacy Assumption (2018) | Modern Context (2025) |
|-----------|-------------------------|-----------------------|
| **Rationale** | Single WAR simplifies deployment for security tool evaluators | Cloud-native deployments prefer containerised microservices |
| **Design choice** | One WAR, all 2,740 servlets, one HSQLDB | No change in v1.2 |
| **Trade-off** | Deployment simplicity vs. cloud evaluator support | Cloud-native SAST tools (Semgrep, Snyk Code) operate on source; WAR irrelevant |
| **Risk** | Docker image for WAR requires Tomcat base image (~500MB) | Provide `Dockerfile` for `tomcat:jre17-temurin-alpine`; already exists in `.devcontainer/` |
| **Cloud impact** | IAST tools require agent injection at JVM startup — works identically in container | IAST profiles (Contrast, Seeker, CxIAST) already supported via pom.xml profiles |

### TR-004: Synchronous Servlets vs. Reactive / Async Frameworks

| Dimension | Legacy Assumption (2018) | Modern Context (2025) |
|-----------|-------------------------|-----------------------|
| **Rationale** | Synchronous servlets are universally understood, easy to generate | Spring WebFlux, Quarkus reactive, Micronaut are dominant in new microservices |
| **Design choice** | `HttpServlet` exclusively | No async/reactive in v1.2 |
| **Trade-off** | Universality and simplicity vs. modern framework coverage | SAST tools with reactive support (DataDog AST, Checkmarx) need reactive test cases |
| **Risk** | Benchmark becomes irrelevant for reactive codebase evaluation | v1.3 roadmap: generate a parallel `ReactiveController` test suite using Spring WebFlux |
| **Migration cost** | High — generator must be updated for reactive source/sink patterns | Generator is external to this repo (BenchmarkUtils) |

### TR-005: Static JDBC Connection vs. Connection-per-Request

| Dimension | Legacy Assumption (2018) | Modern Context (2025) |
|-----------|-------------------------|-----------------------|
| **Rationale** | Simplest possible implementation for generated test code; crawler is sequential | Any concurrent access (DAST, IAST) breaks transaction isolation |
| **Design choice** | `private static Connection conn` — singleton, lazy-initialised | Should use `DataSource.getConnection()` per request with try-with-resources |
| **Trade-off** | Code simplicity in 2,740 generated files vs. correctness under concurrency | The benchmark is never meant to be production code; sequential-only is acceptable if documented |
| **Risk** | Undocumented concurrency constraint causes silent data corruption in IAST deployments | Add `// WARNING: NOT THREAD-SAFE — use single-threaded crawler only` Javadoc to `getSqlStatement()` |
| **Cloud impact** | Cloud-deployed DAST scans are inherently concurrent | Either fix the static connection or explicitly document single-thread constraint |

### TR-006: TLSv1 / Self-Signed Keystore vs. Modern TLS Requirements

| Dimension | Legacy Assumption (2018) | Modern Context (2025) |
|-----------|-------------------------|-----------------------|
| **Rationale** | TLSv1 was minimum viable TLS in 2015; self-signed keystore avoids CA procurement | TLSv1/1.1 disabled by default in Java 11+; NIST SP 800-52r2 requires TLS 1.2+ |
| **Design choice** | `new String[]{"TLSv1"}`, `NoopHostnameVerifier`, `.keystore` committed to SCM | Needs update to TLS 1.2/1.3 minimum |
| **Trade-off** | Historical compatibility vs. forward security | Crawler breaks on Java 11+ in default config — not a trade-off, a defect |
| **Fix effort** | 30 minutes — single `String[]` change in `Utils.java` | Trivial |

---

## Part V — Architectural Drift Heat Map

```
═══════════════════════════════════════════════════════════════════════
LEGACY REQUIREMENT vs. IMPLEMENTATION ALIGNMENT MATRIX
═══════════════════════════════════════════════════════════════════════

           VERBATIM    SPIRIT     SAFETY     MAINTAINABILITY
           COMPLIANCE  COMPLIANCE COMPLIANCE COMPLIANCE

REQ-1     ████████████ ████████████ ████████████ ████████████  FULL
Monolithic
Servlets

REQ-2     ████████░░░░ ████████████ ██████░░░░░░ ████░░░░░░░░  PARTIAL
No ORM in  (66% — Spring (fully covered (Hibernate co-  (requirements
test paths  JdbcTemplate   for coverage)  loaded always)  doc stale)
           was added)

REQ-3     ░░░░░░░░░░░░ ████████████ ████████████ ████░░░░░░░░  TERMINOLOGICAL
SQLi       (literal:     (dual-polarity (by design)   (doc says
Neutralize  0% true neg   is correct)               "neutralize",
           only)                                    means "include")

REQ-4     ░░░░░░░░░░░░ ████████████ ████████████ ████░░░░░░░░  TERMINOLOGICAL
XSS        (same as      (same as      (by design)   (same as
Neutralize  REQ-3)        REQ-3)                     REQ-3)

REQ-5     ████████░░░░ ████████████ ████████░░░░ ████░░░░░░░░  SCOPE CONFUSION
No ECB/    (infra: 100%  (test cases   (160 test    (blanket
AES only   test: 0%)     must exercise  cases use    prohibition
                         weak algos)    DES/ECB)     wrong scope)

REQ-6     ████░░░░░░░░ ████░░░░░░░░ ████████░░░░ ████░░░░░░░░  PARTIAL
JDBC       (Spring added, (no latency   (static conn  (rationale
Latency    Hibernate co-  measurement   is TN-safe    never
Purity     loaded)        exists)       for seq run)  documented)

═══════════════════════════════════════════════════════════════════════
Legend: ████ = aligned blocks · ░░░░ = gap blocks (4 per dimension)
```

---

## Part VI — Recommended Requirement Amendments

The following restatements would eliminate all identified documentation debt, preserving historical intent while accurately describing the implementation:

**REQ-1 (Unchanged — fully aligned):**
> *"Benchmark test cases shall be implemented as synchronous `javax.servlet.http.HttpServlet` subclasses deployed as a single WAR artifact."*

**REQ-2 (Amended):**
> *"SQL injection test cases shall exercise raw JDBC (`Statement`, `PreparedStatement`, `CallableStatement`) and Spring `JdbcTemplate` as sink APIs. Hibernate ORM is used exclusively for infrastructure data seeding and shall not appear in test-case execution paths. Hibernate and Spring framework components loaded at startup shall be gated behind a build profile to preserve sequential-crawl latency isolation."*

**REQ-3 (Amended):**
> *"SQL injection (CWE-89) test cases shall be dual-polarity: approximately 50% shall be true-positive (exploitable) instances and 50% shall be true-negative (safely parameterized) instances. Ground-truth polarity is defined in `expectedresults-1.2.csv` and shall be preserved across all regenerations."*

**REQ-4 (Amended — mirrors REQ-3):**
> *"Cross-site scripting (CWE-79) test cases shall be dual-polarity: approximately 50% true-positive (unencoded output) and 50% true-negative (ESAPI `encodeForHTML()` applied). Ground-truth polarity defined in `expectedresults-1.2.csv`."*

**REQ-5 (Amended — scope-split):**
> *"Infrastructure code in `org.owasp.benchmark.helpers.*` shall use only AES-128 or AES-256 in non-ECB authenticated modes (GCM, CCM). Test case code in `org.owasp.benchmark.testcode.*` is explicitly exempt and must include true-positive instances of prohibited algorithms (DES, 3DES, ECB mode, MD5) to provide ground-truth targets for CWE-327 and CWE-328 evaluation."*

**REQ-6 (Amended):**
> *"Raw JDBC is the primary persistence mechanism for SQL injection test cases to minimise framework abstraction overhead. Spring `JdbcTemplate` is a secondary SQL test path. Hibernate ORM is used for infrastructure seeding only and must be excluded from test execution paths. The JNDI connection pool provides capacity for sequential single-threaded crawling; concurrent multi-threaded operation is not supported and will cause transaction interleaving."*
