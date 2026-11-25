# pca-java — Proof-Carrying Authority verifier for Java

An **offline verifier for Proof-Carrying Actions (PCActns)** in Java. A PCActn is the credential an
autonomous agent presents with *every* action it takes: a self-contained, cryptographically-checkable
object proving the action is a faithful execution of authority its principal actually granted. Your
resource server verifies it locally — no token introspection, no network call on the hot path.

This library is the Java member of the PCA verifier family. It is a faithful port of the TypeScript
reference implementation and passes the **same shared conformance corpus** as every other language
verifier, so a PCActn that verifies here verifies identically everywhere.

## Install

The verifier is a small source package (`net.atlasauth.pca`, in `src/`). Add those sources to your
build, or clone the repo and reference it. It targets a modern JDK and uses BouncyCastle
(`bcprov-jdk18on`) for strict Ed25519 verification.

```java
import net.atlasauth.pca.Pca;
```

## Verify a PCActn

A verifier is stateless. Give it the received PCActn (a parsed `Map`, or raw JSON via
`verifyPcactnJson`), the Root Intent Grant it claims to derive from, the current time (epoch
**milliseconds**), and *your own* audience id. It returns an allow/deny verdict plus the per-check
results.

```java
import net.atlasauth.pca.Pca;

// `raw` is the PCActn as received (strict canonical JSON, wire version 2).
// `grant` is the Root Intent Grant the action's capability chain roots in.
Pca.Verdict verdict = Pca.verifyPcactnJson(
    raw,
    grant,
    System.currentTimeMillis(),
    "https://api.example.com");

if (verdict.allow) {
    // every core check passed — execute the action
} else {
    System.out.println("denied: " + verdict.reason + " " + verdict.checks);
}
```

`verdict.checks` reports each core check (`wire`, `version`, `audience`, `validity`, `chain`,
`plan_inclusion`, `leaf_signature`, `counter`). Every check is **fail-closed** — the action is allowed
only if none reports failure — and a `wire` failure is terminal (nothing else is evaluated).

## Caveats (policy layer)

The verifier above checks that the PCActn is well formed and authentic; like every PCA core verifier it does not decide
whether the action satisfies the grant's caveats. A resource server that enforces caveats evaluates them with its own action
parameters: `net.atlasauth.pca.Caveats.evaluateCaveats(Caveats.policyCaveats(grant, chain), ctx)`. `policy_caveats` is every caveat on the root grant except its first `envelope` caveat (0.4.1: root caveats
are enforced exactly like delegated ones) followed by the caveats the delegation hops appended. Supported types: `expires`,
`not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc` and `max_spend`; any other
type is unsatisfied (fail closed). The `PCA-Action` header must be strict unpadded base64url of UTF-8 text (`Pca.decodePcaHeader(value)` (null when invalid)).

## Acting as an agent (producing proofs)

The SDK also produces the proofs it verifies: an agent written in Java never needs a TypeScript process. The wire is the reference's byte for byte (strict canonical JSON, the same domain strings); Ed25519 outputs are byte-exact against the shared producer vectors, and the post-quantum PCActns it signs (randomised, so not byte vectors) are verified by the reference implementation as well as by this SDK.

Quickstart: mint a grant (the principal's side), hand the agent its key, and let it act.

```java
Keys.SuiteKey me = Keys.ed25519(Keys.edGenerate());          // or Keys.suite("hybrid-ed25519-ml-dsa-65", ed, Keys.pqGenerate(Pq.Prim.ML_DSA_65))
Agent agent = Agent.create(me, "ins_123", grant, null);        // the chain defaults to [grant]
Map<String, Object> pcactn = agent.act("pay", "invoice/7", Issue.obj("amount", 1200L));
HttpRequest req = Agent.attach(HttpRequest.newBuilder(URI.create(url)), pcactn).POST(body).build();   // PCA-Action header
Agent sub = agent.delegate(Keys.ed25519(Keys.edGenerate()), caveats);                                  // narrower sub-agent
```
`Issue` holds the issuer side: `mintGrant`, `delegate`, `commitPlan`, `buildPCActn`, `signDischarge`, `signNarrow`, `signEscalationAnswer`, `signPassport`, `signWorkflow`, `signStepReceipt`, `signReadGrant`, `signAggregateGrant`, `signFreshAt`.

Keys: Ed25519, ML-DSA-65/87 and SLH-DSA-SHA2-128f/256s (where the SDK has the library), the hybrids and the nested hybrid. FN-DSA and LESS cannot be signed here and are refused with `unsupported_suite`. A hybrid or pure post-quantum agent needs its post-quantum public key committed in the grant (`holderPqPk`), and the verifier needs the principal's post-quantum key pinned.

## One call: Protect.protect

`Protect.protect` fills in the secure defaults of a resource server: the grant lookup from your own list or function (never
the request), an in-memory replay store, a revocation source with a `revoke(grantId)` handle, and the single-step plan. It
returns the servlet filter or Spring interceptor and the handle. Anything you set on the config wins over the default.

```java
Protect.Protected p = Protect.protect(new Protect.Config("payments-rs", (request, body) -> operationFor(request, body))
    .grants(grants));            // a List of grants, or a function from grant_ref to a grant
registry.addInterceptor(p.interceptor());   // or register p.filter() as a servlet filter
p.revoke(grantId);                           // every later action under that grant is refused
```

Optional on the config: `stateStore(...)` (use `PcaJdbcStateStore` for several workers), `isRevoked(...)` (consulted in
addition to `revoke`), `clock(...)`, `plan(...)`. This SDK has no connector-catalog risk pricing, so server-side risk inputs are
not derived. A runnable server is in `examples/spring-boot-server`.

## Explain a refusal

`Refusals.explain(reason)` maps a refusal reason (by its leading check name) to what it means, how to fix it and the page that
explains it. It never throws; an unknown reason gets a generic entry that links the table.

```java
Refusals.Help h = Refusals.explain(result.reason);   // h.check(), h.meaning(), h.fix(), h.docs()
```

The filter and interceptor add the same link to every refusal body as a `doc` member
(`https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#replay`); the reason strings are unchanged.

## What a passing result does not cover

`counter: pass` is a format check (a non-negative integer); it does **not** mean the action was not replayed.
Verification is stateless and this package has no replay store, so the resource server must persist, per grant and
agent, the last accepted counter and refuse anything not strictly greater, atomically across all of its processes.

The `PcaFilter` servlet filter runs the core verifier only. It does not check replay, revocation, caveats, envelope predicates, plan
authorization, risk or thresholds, and it does not compare the request body with the signed `params_digest`. Do those
checks in your handler (the caveat helpers above, the params digest of the body you will execute, your replay and
revocation stores), or delegate the decision to a full verifier such as `requirePCA` from `@atlasauth/pca`.

## Conformance

The repo ships a vendored copy of the shared **conformance corpus** (`conformance/vectors.json` +
`conformance/keys.json`): 676 golden and adversarial PCActns with their expected verdicts,
plus canonical-JSON, strict-base64url, and Merkle primitive vectors. The bundled `ConformanceTest`
runs the verifier against every vector; it must reproduce `allow` and every listed check exactly.

## Supported signature suites

- `ed25519` (default)
- `ml-dsa-65` (FIPS-204, post-quantum)
- `hybrid-ed25519-ml-dsa-65` (classical + post-quantum)

ML-DSA-65 verification uses BouncyCastle (>= 1.80). The suite id and the post-quantum key are part of the
signed body, so a downgrade is a signature failure; a hybrid PCActn requires **both** the Ed25519 and the
ML-DSA-65 signature to verify.

## Capability maturity

The PCActn wire format and the eight core offline checks are stable and conformance-covered. The broader
framework surface is implemented and tested in the reference implementation: threshold/step-up co-signing
(a real FROST threshold signature over a DKG-established group key, released only on a Policy-VM allow),
TEE/hardware and model-weights attestation, zero-knowledge proof-of-compliance (a real Groth16 proof),
optimistic bonds and the contestable dispute game, and the malicious-secure MPC Policy VM (SPDZ-style MACs
with abort). A few rungs carry a remaining production requirement, stated plainly rather than hidden
behind a label: a live TEE/hardware attestation needs real SEV-SNP/TDX silicon (the verifier is tested
against real-crypto mock reports); unforgeable FROST guardian custody needs each share in a separate trust
domain / HSM with a network signing protocol (the reference runs the signing round in-process); the MPC
Policy VM's offline triple generation is trusted-dealer today (a no-dealer OT/HE phase is designed); and
the zero-knowledge circuit proves a decision subset (plan-membership + risk ≤ budget), with fuller
policy coverage ongoing. See the [PCA framework repo](https://github.com/Atlas-Authorization/pca) for the
full model.

## License

See `LICENSE`.
