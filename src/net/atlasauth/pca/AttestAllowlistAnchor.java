package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * A transparency anchor for allowlist manifests. A manifest that verifies is only as fresh as the verifier's own memory of it; anchoring
 * records each accepted {@code (issuer, version, digest)} as a leaf of an operator-run append-only Merkle log under a signed tree head, so a
 * verifier can prove that THIS manifest is the one anchored for its version, that no later version of the issuer is anchored (no rollback),
 * and that the log has only grown since a head it cached (no split view). The operator side builds and signs the log; the verifier side,
 * {@link #verifyAllowlistAnchored}, trusts only a pinned log key.
 */
public final class AttestAllowlistAnchor {
    private AttestAllowlistAnchor() {}

    private static final String DOMAIN = "pca-attest-allowlist-anchor/v1";
    private static final Pattern B64U_DIGEST = Pattern.compile("[A-Za-z0-9_-]{43}");
    private static final int MAX_FEED = 100_000;
    private static final double DAY = 86_400_000d;

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    /** The leaf of an entry: {@code hashCanonical({domain, issuer, version, digest})}. Throws on a missing or non-canonical member. */
    public static String allowlistAnchorCommit(Object entry) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("domain", DOMAIN);
        for (String k : new String[] {"issuer", "version", "digest"}) {
            if (!(entry instanceof Map) || !((Map<?, ?>) entry).containsKey(k)) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
            m.put(k, ((Map<?, ?>) entry).get(k));
        }
        return Pca.hashCanonical(IntentJs.normalize(m));
    }

    /** The anchored entry {@code {issuer, version, digest}} of a verified manifest. */
    public static Map<String, Object> anchorEntryOf(Map<String, Object> verified) { return Issue.obj("issuer", verified.get("issuer"), "version", verified.get("version"), "digest", verified.get("digest")); }

    private static boolean validEntry(Object e) {
        if (!(e instanceof Map) || ((Map<?, ?>) e).size() != 3) return false;
        Object issuer = get(e, "issuer"), version = get(e, "version"), digest = get(e, "digest");
        return issuer instanceof String && !((String) issuer).isEmpty() && ((String) issuer).length() <= 200
            && IntentJs.isSafeInteger(version) && IntentJs.num(version) >= 1
            && digest instanceof String && B64U_DIGEST.matcher((String) digest).matches();
    }

    // ---- operator side ----

    /** The operator's log: the Merkle tree, the anchored entries in order and the latest signed head. */
    public static final class Log {
        final MerkleLog ledger = new MerkleLog();
        final String instanceId, principal;
        final List<Map<String, Object>> entries = new ArrayList<>();
        Map<String, Object> latest;

        Log(String instanceId, String principal) { this.instanceId = instanceId; this.principal = principal; }

        /** The anchored entries, in order (copies). */
        public synchronized List<Map<String, Object>> entries() {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Map<String, Object> e : entries) out.add(new LinkedHashMap<>(e));
            return out;
        }

        /** The latest signed tree head, or null before the first anchor. */
        public synchronized Map<String, Object> latest() { return latest; }
    }

    /** An empty log for {@code instanceId} and {@code principal}. */
    public static Log createAllowlistAnchorLog(String instanceId, String principal) { return new Log(instanceId, principal); }

    /** The signing options of an anchor or refresh: the log guardian's Ed25519 seed, the head's timestamp and an optional suite. */
    public static final class SignOptions {
        public byte[] guardianSecret;
        public double nowMs;
        public Pq.SignerSuiteOpts suite;
    }

    private static Map<String, Object> signHead(Log log, SignOptions o) {
        Map<String, Object> head = log.ledger.head();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("instance_id", log.instanceId);
        body.put("principal", log.principal);
        body.put("size", head.get("size"));
        body.put("root", head.get("root"));
        body.put("prev_root", log.latest == null ? "" : log.latest.get("root"));
        body.put("timestamp", o.nowMs);
        log.latest = Ledger.signTreeHead(o.guardianSecret, body, o.suite);
        return log.latest;
    }

    /**
     * Anchor a verified manifest (the result of {@link AttestAllowlist#verifyAllowlistManifest}) or an entry {@code {issuer, version, digest}}:
     * append its leaf and sign a new head. Anchoring the same entry again is idempotent; the same version with another digest, or a version
     * lower than one already anchored for the issuer, throws. Returns the evidence for the entry's leaf.
     */
    public static synchronized Map<String, Object> anchorAllowlistHead(Log log, Object what, SignOptions opts) {
        if (!(what instanceof Map)) throw new IllegalArgumentException("Cannot use 'in' operator to search for 'body'");
        Map<String, Object> entry = ((Map<?, ?>) what).containsKey("body") ? Issue.obj("issuer", get(what, "issuer"), "version", get(what, "version"), "digest", get(what, "digest"))
            : new LinkedHashMap<>(StoreJs.map(what));
        if (!validEntry(entry)) throw new IllegalArgumentException("anchorAllowlistHead: malformed entry");
        int same = -1;
        for (int i = 0; i < log.entries.size() && same < 0; i++) {
            Map<String, Object> e = log.entries.get(i);
            if (entry.get("issuer").equals(e.get("issuer")) && IntentJs.num(e.get("version")).equals(IntentJs.num(entry.get("version")))) same = i;
        }
        int index;
        if (same >= 0) {
            if (!log.entries.get(same).get("digest").equals(entry.get("digest"))) throw new IllegalStateException("anchorAllowlistHead: this version is already anchored with a different digest");
            index = same;
        } else {
            double max = 0;
            for (Map<String, Object> e : log.entries) if (e.get("issuer").equals(entry.get("issuer"))) max = Math.max(max, IntentJs.num(e.get("version")));
            if (IntentJs.num(entry.get("version")) < max) throw new IllegalStateException("anchorAllowlistHead: version " + entry.get("version") + " is lower than the anchored " + AttestCommon.jsNumString(max));
            index = log.ledger.appendCommitment(allowlistAnchorCommit(entry));
            log.entries.add(entry);
            signHead(log, opts);
        }
        if (log.latest == null) signHead(log, opts);
        return evidenceFor(log, index, null);
    }

    /** Sign a fresh head over the current tree (a new timestamp, no new entry). Throws when nothing is anchored yet. */
    public static synchronized Map<String, Object> refreshAnchorHead(Log log, SignOptions opts) {
        if (log.ledger.size() == 0) throw new IllegalStateException("refreshAnchorHead: nothing anchored yet");
        return signHead(log, opts);
    }

    /**
     * The evidence a verifier needs for the entry at {@code index}: the latest head, the full feed of entries, the inclusion proof and,
     * when the verifier cached a head of {@code cachedSize} (0 &lt; cachedSize &lt; the head's size), the consistency proof from it.
     */
    public static synchronized Map<String, Object> evidenceFor(Log log, long index, Long cachedSize) {
        if (log.latest == null) throw new IllegalStateException("evidenceFor: log has no signed head");
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("head", log.latest);
        ev.put("entries", new ArrayList<Object>(log.entries()));
        ev.put("proof", log.ledger.inclusionProof(index));
        long headSize = (long) (double) IntentJs.num(log.latest.get("size"));
        if (cachedSize != null && cachedSize > 0 && cachedSize < headSize) ev.put("consistency", log.ledger.consistencyProof(cachedSize, headSize));
        return ev;
    }

    // ---- verifier side ----

    private static Map<String, Object> no(String code, String reason) { return Issue.obj("ok", false, "code", code, "reason", reason); }

    private static boolean finiteOrAbsent(Map<String, Object> opts, String key) { return !opts.containsKey(key) || IntentJs.isFinite(opts.get(key)); }

    /**
     * Verify that {@code verified} (an {@code {issuer, version, digest}} entry or a verified manifest) is anchored in the operator's log:
     * {@code evidence = {head, entries, proof, consistency?}} against {@code opts = {trust: {logKey, instanceId, principal, witnesses?, pqPins?},
     * nowMs, maxHeadAgeMs?, clockSkewMs?, cachedHead?}}. In order: the evidence is complete; the head is signed by the PINNED log key (and the
     * required witnesses) for this log; it is fresh (default age one day, skew one minute); a cached head is genuine and the new head extends
     * it (a smaller head is a rollback, an equal size with another root a split view, a larger one needs a consistency proof); the feed
     * reproduces the signed root; the issuer's log has no two digests for a version; the inclusion proof places the entry under the root; no
     * later version of the issuer is anchored; and the entry is the one anchored for its version. Returns {@code {ok: true, issuer, version,
     * digest, highestAnchoredVersion, head}} or {@code {ok: false, code, reason}}. Never throws.
     */
    public static Map<String, Object> verifyAllowlistAnchored(Map<String, Object> verified, Object evidence, Map<String, Object> opts) {
        try {
            if (!(evidence instanceof Map) || !((Map<?, ?>) evidence).containsKey("proof") || !((Map<?, ?>) evidence).containsKey("head") || !(get(evidence, "entries") instanceof List)) {
                return no("missing-proof", "no anchor evidence (head + entries + inclusion proof) supplied");
            }
            Map<String, Object> ev = StoreJs.map(evidence);
            Object trustO = opts.get("trust");
            if (!(trustO instanceof Map)) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'logKey')");
            Map<String, Object> trust = StoreJs.map(trustO);
            if (!IntentJs.isSafeInteger(opts.get("nowMs"))) return no("bad-head", "nowMs must be an integer");
            double nowMs = IntentJs.num(opts.get("nowMs"));
            Object head = ev.get("head");
            String logKey = trust.get("logKey") instanceof String ? (String) trust.get("logKey") : null;
            Map<String, Object> witnesses = StoreJs.map(trust.get("witnesses")), pins = StoreJs.map(trust.get("pqPins"));
            if (!Ledger.verifyTreeHead(head, logKey, witnesses, pins)) return no("bad-head", "tree head is not signed by the pinned log key (or lacks the required witness cosignatures)");
            if (!Ledger.jsEq(get(head, "instance_id"), trust.get("instanceId")) || !Ledger.jsEq(get(head, "principal"), trust.get("principal"))) return no("bad-head", "tree head is for a different log");
            if (!finiteOrAbsent(opts, "clockSkewMs")) return no("bad-head", "clockSkewMs must be a finite number");
            if (!finiteOrAbsent(opts, "maxHeadAgeMs")) return no("bad-head", "maxHeadAgeMs must be a finite number");
            double skew = Math.max(0, opts.containsKey("clockSkewMs") ? IntentJs.num(opts.get("clockSkewMs")) : 60_000);
            double maxAge = opts.containsKey("maxHeadAgeMs") ? IntentJs.num(opts.get("maxHeadAgeMs")) : DAY;
            if (!IntentJs.isSafeInteger(get(head, "timestamp"))) return no("stale-head", "tree head is timestamped in the future");
            double ts = IntentJs.num(get(head, "timestamp"));
            if (ts > nowMs + skew) return no("stale-head", "tree head is timestamped in the future");
            if (!(nowMs - ts <= maxAge)) return no("stale-head", "tree head is older than maxHeadAgeMs (" + AttestCommon.jsNumString(maxAge) + ")");

            double headSize = IntentJs.num(get(head, "size"));
            if (opts.containsKey("cachedHead")) {
                Object cached = opts.get("cachedHead");
                if (!Ledger.verifyTreeHead(cached, logKey, witnesses, pins) || !Ledger.jsEq(get(cached, "instance_id"), trust.get("instanceId")) || !Ledger.jsEq(get(cached, "principal"), trust.get("principal"))) {
                    return no("bad-cache", "the cached head does not verify under the pinned log key");
                }
                double cachedSize = IntentJs.num(get(cached, "size"));
                if (headSize < cachedSize) return no("log-rollback", "head size " + AttestCommon.jsNumString(headSize) + " < cached " + AttestCommon.jsNumString(cachedSize) + ": the log shrank");
                if (headSize == cachedSize) {
                    if (!Ledger.jsEq(get(head, "root"), get(cached, "root"))) return no("split-view", "two different roots at the same size: split view / fork");
                } else if (!ev.containsKey("consistency") || !Ledger.verifyHeadConsistency(cached, head, ev.get("consistency"), logKey, witnesses, pins)) {
                    return no("inconsistent-with-cache", "no valid consistency proof from the cached head: forked or truncated log");
                }
            }

            List<?> entries = (List<?>) ev.get("entries");
            if (entries.size() > MAX_FEED || (double) entries.size() != headSize) return no("feed-mismatch", "entries do not match the signed tree size");
            for (Object e : entries) if (!validEntry(e)) return no("feed-mismatch", "entries do not match the signed tree size");
            List<String> commits = new ArrayList<>();
            for (Object e : entries) commits.add(allowlistAnchorCommit(e));
            if (!Ledger.ledgerRootOf(commits).equals(get(head, "root"))) return no("feed-mismatch", "entries do not reproduce the signed root");

            Object issuer = verified.get("issuer"), version = verified.get("version"), digest = verified.get("digest");
            double mineVersion = IntentJs.num(version);
            double highest = 0;
            boolean anchored = false;
            Map<Double, Object> firstDigest = new LinkedHashMap<>();
            for (Object eo : entries) {
                if (!Ledger.jsEq(get(eo, "issuer"), issuer)) continue;
                double ver = IntentJs.num(get(eo, "version"));
                highest = Math.max(highest, ver);
                Object prior = firstDigest.putIfAbsent(ver, get(eo, "digest"));
                if (prior != null && !prior.equals(get(eo, "digest"))) return no("log-conflict", "log anchors two different digests for version " + AttestCommon.jsNumString(ver));
                if (ver == mineVersion && Ledger.jsEq(get(eo, "digest"), digest)) anchored = true;
            }
            String myCommit = allowlistAnchorCommit(Issue.obj("issuer", issuer, "version", version, "digest", digest));
            Object proof = ev.get("proof");
            if (proof == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'size')");
            if (!Ledger.jsEq(get(proof, "size"), get(head, "size"))) return no("bad-proof", "inclusion proof size does not match the signed head size");
            if (!Ledger.verifyLedgerInclusion((String) get(head, "root"), proof, myCommit)) return no("bad-proof", "inclusion proof does not place this manifest under the signed root");
            if (mineVersion < highest) return no("anchored-rollback", "manifest version " + AttestCommon.jsNumString(mineVersion) + " < highest anchored " + AttestCommon.jsNumString(highest) + " for '" + issuer + "'");
            if (!anchored) return no("not-anchored", "this manifest digest is not the one anchored for its version");
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("ok", true);
            ok.put("issuer", issuer);
            ok.put("version", version);
            ok.put("digest", digest);
            ok.put("highestAnchoredVersion", StoreJs.num(highest));
            ok.put("head", head);
            return ok;
        } catch (RuntimeException e) {
            return no("bad-head", e.getMessage() == null ? "anchor verification error" : e.getMessage());
        }
    }
}
