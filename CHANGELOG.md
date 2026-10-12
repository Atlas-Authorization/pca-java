# Changelog

## 0.4.1

- Security (policy layer): caveats on the root grant outside the envelope are now evaluated like delegated caveats; new policy_caveats/evaluate_caveats helpers (incl. max_spend). The core verifier still does not evaluate caveats. Java: `Caveats.policyCaveats(grant, chain)` (the grant's caveats minus its first `envelope` caveat, then the caveats the hops appended) and `Caveats.evaluateCaveats(caveats, ctx)` -> `Caveats.Result{ok, failed}` (total; `expires`, `not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc`, and the new `max_spend {usd}`; anything else fails closed). `Pca.verifyPcactn`, `PcaFilter` and `PcaInterceptor` are unchanged and still treat caveats as opaque: a resource server enforcing a grant's caveats calls `Caveats.evaluateCaveats(Caveats.policyCaveats(grant, chain), ctx)` with its own action params. New `primitives.caveat_eval` vectors run in `ConformanceTest`.
- Wire: threshold-share signatures are validated per suite (`Pq.validateShareSignatureWire`): `alg` absent = ed25519 (64-byte `sig`, no `pq_sig`), `ml-dsa-65` (3309-byte `sig`, no `pq_sig`), `hybrid-ed25519-ml-dsa-65` (64-byte `sig` + 3309-byte `pq_sig`); a non-string (incl. null) or unknown `alg` is a wire refusal. Before, every share `sig` had to be 64 bytes, so a pure ML-DSA-65 share could not be carried. A share's `pq_pk` is still judged only by the threshold check. Reason text is now `threshold.shares[i]: 'sig' is not canonical base64url (N bytes) for alg '<alg>'`. `ConformanceTest` skips a vector whose `requires` names a registered suite this verifier does not implement.
- Middleware: the `PCA-Action` header is decoded STRICTLY (`Pca.decodePcaHeader`, null when invalid): unpadded base64url only, nothing trimmed (a whitespace-only, padded, standard-alphabet or whitespace-carrying value is a 401 `not canonical base64url`, where it was trimmed or treated as absent), and the bytes must be well-formed UTF-8 (overlong forms, encoded surrogates and truncated sequences are refused; they were replaced with U+FFFD). Only an absent or empty header falls back to the body. New `primitives.pca_header` vectors run in `ConformanceTest` and `PcaMiddlewareTest`.
- Tests: `PqChainTest.signerSetRegistry` expected a stray `pq_pk` on an ed25519 share to be ignored; since d00dba73 such a share is refused (the test was stale).
- Version: this source-only package has no version field (the pom is the PIT build, version 0); this entry is 0.4.1.

## Unreleased (BREAKING)

- Depth / R6-05 (parity + robustness): every protocol digest (capHash and the hop body digest, Merkle leaves, params / conditions digests, the threshold signer-set hash) now uses the STRICT canonical form, exactly as the reference `hash.ts` `canonicalBytes`. Before, these were hashed under the lenient form, so a hop or leaf signed over out-of-profile bytes (nesting deeper than 32, a lone surrogate, a non-canonical number) verified where the reference refuses it, and a deeply nested (or cyclic) caveat, Merkle leaf or grant overflowed the stack: the `StackOverflowError` escaped `verifyChain` / `verifyInclusion` / `verifyPcactn` (they catch only `RuntimeException`). The public lenient `Json.canonicalize` is capped at `Json.MAX_LENIENT_DEPTH` (512). `Pca.verifyPcactnJson(null, ...)` is a wire refusal (`strict JSON: input is not a string`), not a NullPointerException. Shared `primitives.depth` vectors (limit-1 / limit / limit+1 / 100000 per entry point) run in the conformance runner on a 512 KiB stack.
- R6-03/R6-04 (parity): `Threshold.verifyShare` validates the WHOLE signer set like the reference (unknown / wrong-case roles, malformed keys, empty / null / short `pq_pk` anywhere, one key per role, one role per key, a duplicate (role, key) only with the same `pq_pk`); `share.role` is required; `t` must be 1, 2 or 3. New total entry points `Threshold.verifyShareEntry(Object)` and `Threshold.signerSetHashB64u(Object)`.
- R6-05 (robustness + parity): `Pca.verifyChain` applies the reference per-hop type check (`wellTyped`: string id/issuer/holder/body_digest/sig, optional alg/pq_pk/pq_sig/holder_pq/parent absent or string, caveats objects with a string `type`), so a correctly SIGNED hop with ill-typed caveats is refused (it was accepted); `verifyChain` and `verifyPcactn` never throw.
- R6-02 (security): a signer-set role that registers a `pq_pk` now REQUIRES a PQ (pure or hybrid) threshold share; an ed25519-only share for that role is refused, so an Ed25519 break no longer forges a hybrid-registered role (parity with the TypeScript reference). Corpus: `agent-bound-signerset-with-pq-pk` is now `valid:false`; new positive `agent-hybrid-signerset-with-pq-pk`.
- R5-A1 (security): threshold-share verification is now signer-set PINNED, no longer self-vouched. The share must be for the one key the signer set registers for its role, a PQ/hybrid share verifies only under the set's registered `pq_pk` (a differing share `pq_pk` is refused), the share-suite tag is part of the signed bytes (a classical share cannot be relabelled hybrid), and the signer-set hash now includes a registered `pq_pk` (parity with the TypeScript reference). New corpus vectors: `agent-not-in-signer-set`, `agent-bound-signerset-with-pq-pk`, `agent-hybrid-relabel-*`.

- Suite policy defaults documented: no list = no restriction, an empty list refuses everything, and the hosted API defaults to ed25519 + Ed25519 hybrids (README lists the exact list to pass offline).

- **R4-01: the standalone `Pca.verifyChain` no longer verifies a non-Ed25519 root under the root's own `pq_pk`.** A pure
  `ml-dsa-65` or `hybrid-ed25519-ml-dsa-65` ROOT hop (hop 0) previously verified under the `pq_pk` carried by the root
  artifact itself, so an attacker-minted root naming a victim Ed25519 issuer, signed with the attacker's own ML-DSA key,
  was accepted. The PQ key for hop 0 must now come from the verifier:
  - new trailing parameters `Map<String,Object> pqPins` (root issuer Ed25519 b64u -> PQ public key b64u) and
    `Map<String,Object> trustedRoot` (the verifier's own stored root capability):
    `verifyChain(chain, expectedRootIssuer, haveIssuer, allowed, pqPins, trustedRoot)`. The 4-argument overload remains
    and behaves as `pqPins = null, trustedRoot = null`.
  - accepted if `trustedRoot` has the same `cap_hash` as the root (its `pq_pk` is used), else if `pqPins` has an own entry
    for `root.issuer` equal to `root.pq_pk` (a differing pin is a refusal, no fallback). Otherwise refused with
    `hop 0: root suite '<alg>' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)`.
  - Ed25519 roots are unaffected. Hops >= 1 and the PCActn leaf still resolve their key from the parent holder's
    `holder_pq` commitment.
  - Migration: callers of the standalone chain API that accept PQ roots must pass `pqPins` or `trustedRoot`; without them a
    PQ root is now refused.
  - The PCActn path (`verifyPcactn` / `verifyPcactnJson`) is unchanged in behaviour: it already requires `chain[0]` to be
    byte-identical to the grant and passes that grant as `trustedRoot`.
  - Structure: `Pq.resolvePqKey` is the single producer of an opaque `Pq.PinnedPq`; the suite verifier accepts only that
    type. Threshold shares and the `pq_artifact` primitives use the explicitly named `verifyLeafSuiteCallerVouched`.
