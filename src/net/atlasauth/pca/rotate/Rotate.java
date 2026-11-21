package net.atlasauth.pca.rotate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.revoke.JsVal;

/**
 * Key rotation and subtree revocation for Proof-Carrying Authority capability chains. Every re-issue goes through the core
 * builders ({@link Issue#mintRoot}, {@link Issue#delegate}); nothing here re-implements signing or hashing. Attenuation is
 * preserved by construction: each re-issued hop carries exactly the caveats the hop it replaces carried, so a re-issue never
 * widens authority. Each function returns the new chain together with a {@link RevocationRecord} for the old key or subtree.
 *
 * <p>Chains are lists of capability objects (Map). A chain whose hops lack a string id / issuer / holder or a caveats list is
 * refused (the reference passes such hops through untouched).
 */
public final class Rotate {
    private Rotate() {}

    /** The result of a rotation or re-issue: the new chain plus the revocation record for the old key(s). */
    public static final class RotationResult {
        public final List<Map<String, Object>> chain;
        public final RevocationRecord revocation;
        RotationResult(List<Map<String, Object>> chain, RevocationRecord revocation) { this.chain = chain; this.revocation = revocation; }
    }

    /** The result of {@link #compromisedKeyFlow}. */
    public static final class CompromisedFlow {
        public final List<RevocationRecord> revocations;
        public final List<Map<String, Object>> reissued;
        CompromisedFlow(List<RevocationRecord> revocations, List<Map<String, Object>> reissued) { this.revocations = revocations; this.reissued = reissued; }
    }

    // ---- internal helpers ----

    private static String pub(Keys.EdKey secret) {
        if (secret == null) throw new JsVal.TypeError("expected a secret key");
        return secret.id();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> chainOf(Object chain, String ctx) {
        if (!(chain instanceof List) || ((List<?>) chain).isEmpty()) throw new IllegalArgumentException(ctx + ": empty chain");
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object hop : (List<Object>) chain) {
            if (!(hop instanceof Map)) throw new JsVal.TypeError(ctx + ": malformed capability");
            Map<String, Object> h = (Map<String, Object>) hop;
            if (!JsVal.nonEmpty(h.get("id")) || !(h.get("issuer") instanceof String) || !(h.get("holder") instanceof String)) throw new JsVal.TypeError(ctx + ": a capability needs a string id, issuer and holder");
            if (!(h.get("caveats") instanceof List)) throw new JsVal.TypeError("malformed capability: caveats must be arrays");
            out.add(h);
        }
        return out;
    }

    private static String s(Map<String, Object> c, String k) { return (String) c.get(k); }

    @SuppressWarnings("unchecked")
    private static List<Object> appendedCaveats(Map<String, Object> parent, Map<String, Object> child) {
        List<Object> pc = (List<Object>) parent.get("caveats"), cc = (List<Object>) child.get("caveats");
        if (cc.size() < pc.size()) throw new IllegalArgumentException("malformed chain: a child carries fewer caveats than its parent (not an attenuation)");
        return new ArrayList<>(cc.subList(pc.size(), cc.size()));
    }

    private static void checkNow(Double now, String ctx) {
        if (now != null && (now.isNaN() || now.isInfinite())) throw new JsVal.TypeError(ctx + ": now must be a finite number");
    }

    private static double at(Double now) { return now != null ? now : (double) System.currentTimeMillis(); }

    private static String or(String a, String b) { return a != null ? a : b; }

    private static Map<String, Object> delegate(Map<String, Object> parent, String toHolder, List<Object> added, Keys.EdKey signer) {
        return Issue.delegate(parent, toHolder, added, Keys.ed25519(signer), null);
    }

    // ---- agent (leaf holder) key rotation ----

    /**
     * Rotate the AGENT (leaf holder) key: the leaf's parent re-signs the leaf delegation, re-binding it to newKeyPair's public
     * key while preserving the leaf's exact caveats. oldHolderSecret is the secret that re-signs the leaf hop, i.e. the leaf's
     * issuer (the parent's holder key); the call throws when it does not match. A root-only chain has no leaf delegation to
     * re-issue: use {@link #rotatePrincipalKey}. reason and now are optional (null).
     */
    public static RotationResult rotateAgentKey(Object chainIn, Keys.EdKey oldHolderSecret, Keys.EdKey newKeyPair, String reason, Double now) {
        List<Map<String, Object>> chain = chainOf(chainIn, "rotateAgentKey");
        if (chain.size() < 2) throw new IllegalArgumentException("rotateAgentKey: a root-only chain has no leaf delegation to re-issue; use rotatePrincipalKey");
        Map<String, Object> parent = chain.get(chain.size() - 2), leaf = chain.get(chain.size() - 1);
        String signerPub = pub(oldHolderSecret);
        if (!signerPub.equals(s(leaf, "issuer"))) {
            throw new IllegalArgumentException("rotateAgentKey: oldHolderSecret (pub " + signerPub + ") is not the leaf's issuer " + s(leaf, "issuer")
                + "; the leaf is re-signed by its parent holder (the leaf issuer)");
        }
        if (newKeyPair == null) throw new JsVal.TypeError("rotateAgentKey: newKeyPair is required");
        String newHolder = newKeyPair.id();
        if (newHolder.equals(s(leaf, "holder"))) throw new IllegalArgumentException("rotateAgentKey: newKeyPair is the key being rotated out");
        checkNow(now, "rotateAgentKey");
        Map<String, Object> newLeaf = delegate(parent, newHolder, appendedCaveats(parent, leaf), oldHolderSecret);
        List<Map<String, Object>> newChain = new ArrayList<>(chain.subList(0, chain.size() - 1));
        newChain.add(newLeaf);
        return new RotationResult(newChain, new RevocationRecord(s(leaf, "id"), s(leaf, "holder"), s(leaf, "issuer"), null, List.of(s(leaf, "id")),
            or(reason, "agent key rotated"), at(now)));
    }

    // ---- principal (root) key rotation / re-root ----

    /**
     * Rotate the PRINCIPAL (root) key by re-rooting: mint a fresh root under newPrincipalKeyPair bound to the same agent holder
     * and root caveats, then re-issue every downstream hop onto it (holders unchanged, so each hop is re-signed by the same
     * issuer secret it had; supply them in holderSecrets, chain order, one per non-root hop). Pass the full chain, or null
     * chain and oldRoot for a root-only chain. oldPrincipalSecret must be the current root's issuer.
     */
    public static RotationResult rotatePrincipalKey(Object chainIn, Object oldRoot, Keys.EdKey oldPrincipalSecret, Keys.EdKey newPrincipalKeyPair,
                                                    List<Keys.EdKey> holderSecretsIn, String reason, Double now) {
        Object raw = chainIn != null ? chainIn : (JsVal.truthy(oldRoot) ? List.of(oldRoot) : List.of());
        List<Map<String, Object>> chain = chainOf(raw, "rotatePrincipalKey");
        Map<String, Object> root = chain.get(0);
        if (root.containsKey("parent")) throw new IllegalArgumentException("rotatePrincipalKey: chain[0] is not a root (it has a parent)");
        String oldPub = pub(oldPrincipalSecret);
        if (!oldPub.equals(s(root, "issuer"))) throw new IllegalArgumentException("rotatePrincipalKey: oldPrincipalSecret (pub " + oldPub + ") is not the root's issuer " + s(root, "issuer"));
        List<Keys.EdKey> holderSecrets = holderSecretsIn != null ? holderSecretsIn : List.of();
        if (holderSecrets.size() != chain.size() - 1) {
            throw new IllegalArgumentException("rotatePrincipalKey: expected " + (chain.size() - 1) + " holderSecrets (one per non-root hop), got " + holderSecrets.size());
        }
        if (newPrincipalKeyPair == null) throw new JsVal.TypeError("rotatePrincipalKey: newPrincipalKeyPair is required");
        String newPub = newPrincipalKeyPair.id();
        if (newPub.equals(s(root, "issuer"))) throw new IllegalArgumentException("rotatePrincipalKey: newPrincipalKeyPair is the key being rotated out");
        checkNow(now, "rotatePrincipalKey");
        @SuppressWarnings("unchecked")
        List<Object> rootCaveats = (List<Object>) root.get("caveats");
        Map<String, Object> newRoot = Issue.mintRoot(Keys.ed25519(newPrincipalKeyPair), s(root, "holder"), null, rootCaveats);
        List<Map<String, Object>> newChain = new ArrayList<>();
        newChain.add(newRoot);
        for (int i = 1; i < chain.size(); i++) {
            Map<String, Object> oldParent = chain.get(i - 1), oldChild = chain.get(i);
            Keys.EdKey signer = holderSecrets.get(i - 1);
            String signerPub = pub(signer);
            if (!signerPub.equals(s(oldChild, "issuer"))) {
                throw new IllegalArgumentException("rotatePrincipalKey: holderSecret for hop " + i + " (pub " + signerPub + ") is not that hop's issuer " + s(oldChild, "issuer"));
            }
            newChain.add(delegate(newChain.get(i - 1), s(oldChild, "holder"), appendedCaveats(oldParent, oldChild), signer));
        }
        List<String> ids = new ArrayList<>();
        for (Map<String, Object> c : chain) ids.add(s(c, "id"));
        return new RotationResult(newChain, new RevocationRecord(s(root, "id"), s(root, "holder"), s(root, "issuer"), s(root, "id"), ids,
            or(reason, "principal key rotated (re-root)"), at(now)));
    }

    // ---- compromised-subtree revoke + re-issue ----

    private static int indexOfHolder(List<Map<String, Object>> chain, String holder) {
        for (int i = 0; i < chain.size(); i++) if (s(chain.get(i), "holder").equals(holder)) return i;
        return -1;
    }

    /**
     * Treat compromisedHolder as COMPROMISED: revoke the hop it first holds and every descendant, and re-issue a fresh chain from
     * the nearest safe ancestor (the hop just above) down to a brand-new key, carrying the caveats of the subtree's deepest leaf
     * so the re-issued authority is never wider. ancestorSecret must be the safe ancestor's holder secret. Throws when the holder
     * is not in the chain or is the root holder (rotate the root with {@link #rotatePrincipalKey}).
     */
    public static RotationResult revokeAndReissueSubtree(Object chainIn, String compromisedHolder, Keys.EdKey newKeyPair, Keys.EdKey ancestorSecret, String reason, Double now) {
        List<Map<String, Object>> chain = chainOf(chainIn, "revokeAndReissueSubtree");
        int idx = indexOfHolder(chain, compromisedHolder);
        if (idx < 0) throw new IllegalArgumentException("revokeAndReissueSubtree: holder " + compromisedHolder + " is not in the chain");
        if (idx == 0) {
            throw new IllegalArgumentException("revokeAndReissueSubtree: the compromised holder is the root holder (no safe delegation ancestor); rotate the root with rotatePrincipalKey");
        }
        Map<String, Object> ancestor = chain.get(idx - 1), subtreeRoot = chain.get(idx), leaf = chain.get(chain.size() - 1);
        String ancestorPub = pub(ancestorSecret);
        if (!ancestorPub.equals(s(ancestor, "holder"))) {
            throw new IllegalArgumentException("revokeAndReissueSubtree: ancestorSecret (pub " + ancestorPub + ") is not the safe ancestor's holder " + s(ancestor, "holder"));
        }
        if (newKeyPair == null) throw new JsVal.TypeError("revokeAndReissueSubtree: newKeyPair is required");
        String newHolder = newKeyPair.id();
        for (Map<String, Object> c : chain.subList(idx, chain.size())) {
            if (s(c, "holder").equals(newHolder)) throw new IllegalArgumentException("revokeAndReissueSubtree: newKeyPair is a key held inside the compromised subtree");
        }
        checkNow(now, "revokeAndReissueSubtree");
        Map<String, Object> newHop = delegate(ancestor, newHolder, appendedCaveats(ancestor, leaf), ancestorSecret);
        List<Map<String, Object>> reissued = new ArrayList<>(chain.subList(0, idx));
        reissued.add(newHop);
        List<String> revokedIds = new ArrayList<>();
        for (Map<String, Object> c : chain.subList(idx, chain.size())) revokedIds.add(s(c, "id"));
        return new RotationResult(reissued, new RevocationRecord(s(subtreeRoot, "id"), compromisedHolder, s(subtreeRoot, "issuer"), s(subtreeRoot, "id"), revokedIds,
            or(reason, "delegation subtree compromised"), at(now)));
    }

    /**
     * Handle a compromised key end to end: one revocation record per capability in the compromised subtree (root to leaf, so a
     * registry can revoke each id) plus the re-issued chain from the nearest safe ancestor.
     */
    public static CompromisedFlow compromisedKeyFlow(Object chainIn, String compromisedHolder, Keys.EdKey newKeyPair, Keys.EdKey ancestorSecret, String reason, Double now) {
        List<Map<String, Object>> chain = chainOf(chainIn, "compromisedKeyFlow");
        int idx = indexOfHolder(chain, compromisedHolder);
        if (idx < 0) throw new IllegalArgumentException("compromisedKeyFlow: holder " + compromisedHolder + " is not in the chain");
        List<Map<String, Object>> reissued = revokeAndReissueSubtree(chain, compromisedHolder, newKeyPair, ancestorSecret, reason, now).chain;
        Map<String, Object> subtreeRoot = chain.get(idx);
        double revokedAt = at(now);
        String why = or(reason, "delegation subtree compromised");
        List<RevocationRecord> revocations = new ArrayList<>();
        for (Map<String, Object> c : chain.subList(idx, chain.size())) {
            revocations.add(new RevocationRecord(s(c, "id"), s(c, "holder"), s(c, "issuer"), s(subtreeRoot, "id"), List.of(s(c, "id")), why, revokedAt));
        }
        return new CompromisedFlow(revocations, reissued);
    }

    // ---- atomic rotate-and-revoke ----

    /**
     * Revoke what a rotation replaced, all or nothing. Every capability id the record(s) cover is revoked in sink; if any revoke
     * throws, the ones this call added are removed again and the error is rethrown, so a failed rotation never leaves the old chain
     * half revoked. It revokes capability ids only (not the holder / issuer keys). It refuses, before touching the sink, a record
     * that names no capability id and a re-issued chain that shares an id with what is being revoked. records is one record or a
     * list of them (each a Map, as {@link RevocationRecord#toMap}); reissued may be null.
     */
    public static List<String> applyRotation(RevocationSink sink, Object records, Object reissued) {
        List<?> list = records instanceof List ? (List<?>) records : java.util.Collections.singletonList(records);
        Map<String, Object> todo = new LinkedHashMap<>();
        for (Object r : list) {
            Object capIds = JsVal.member(r, "capIds");
            List<?> ids;
            if (capIds != null) {
                // `r.capIds ?? ...` then iterating: anything that is not a list cannot be iterated as ids
                if (!(capIds instanceof List)) throw new JsVal.TypeError("applyRotation: a record names an invalid capability id");
                ids = (List<?>) capIds;
            } else {
                Object one = JsVal.member(r, "capId");
                ids = !JsVal.has(r, "capId") ? List.of() : java.util.Collections.singletonList(one);
            }
            for (Object id : ids) {
                if (!JsVal.nonEmpty(id)) throw new JsVal.TypeError("applyRotation: a record names an invalid capability id");
                todo.putIfAbsent((String) id, r);
            }
        }
        if (todo.isEmpty()) throw new IllegalArgumentException("applyRotation: the record names no capability to revoke");
        Set<Object> kept = new LinkedHashSet<>();
        if (reissued != null) {
            if (!(reissued instanceof List)) throw new JsVal.TypeError("applyRotation: reissued must be a list");
            for (Object c : (List<?>) reissued) kept.add(JsVal.member(c, "id"));
        }
        for (String id : todo.keySet()) {
            if (kept.contains(id)) throw new IllegalArgumentException("applyRotation: the re-issued chain contains a capability that is being revoked");
        }
        List<String> added = new ArrayList<>();
        try {
            for (Map.Entry<String, Object> e : todo.entrySet()) {
                String id = e.getKey();
                Object r = e.getValue();
                if (sink.lookup("cap", id) == null) added.add(id);
                Map<String, Object> in = RevocationSink.capKey(id);
                in.put("value", id);
                if (JsVal.has(r, "reason")) in.put("reason", JsVal.member(r, "reason"));
                if (JsVal.has(r, "revokedAt")) in.put("revokedAt", JsVal.member(r, "revokedAt"));
                sink.revoke(in);
            }
        } catch (RuntimeException e) {
            for (String id : added) {
                try { sink.unrevoke(RevocationSink.capKey(id)); } catch (RuntimeException ignored) { /* best effort: the original failure is the one to report */ }
            }
            throw e;
        }
        return new ArrayList<>(todo.keySet());
    }

    /** Typed overload of {@link #applyRotation(RevocationSink, Object, Object)}. */
    public static List<String> applyRotation(RevocationSink sink, List<RevocationRecord> records, List<Map<String, Object>> reissued) {
        List<Object> maps = new ArrayList<>();
        for (RevocationRecord r : records) maps.add(r.toMap());
        return applyRotation(sink, (Object) maps, (Object) reissued);
    }
}
