package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link ActionRegistry} beyond the k05 oracle: inputs signed here (registry and principal keys of this
 * test), so every branch of the pin decision, the re-approval, the registry signature and the pack tracker is reached with a
 * valid signature and asserted exactly.
 */
public class ActionRegistryRestKillTest {
    static byte[] seed(int b) { byte[] s = new byte[32]; Arrays.fill(s, (byte) b); return s; }

    static final Keys.EdKey REG = Keys.edFromSeed(seed(11));
    static final Keys.EdKey PRINCIPAL = Keys.edFromSeed(seed(12));
    static final String NS = "stripe", VERB = "stripe.refund";
    static final String GID = d("grant");

    static String d(String tag) { return Pca.hashCanonical(tag); }

    static Map<String, Object> m(Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        return o;
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    static List<Object> keys() { return list(m("kid", "reg-1", "alg", "ed25519", "pk", REG.id())); }

    static Map<String, Object> without(Map<String, Object> x, String k) { Map<String, Object> o = new LinkedHashMap<>(x); o.remove(k); return o; }

    /** A registry-signed evolution record. */
    static Map<String, Object> rec(String ns, String verb, String from, String to, String cls) {
        Map<String, Object> r = m("v", 1, "kind", "pca-evolution-record", "ns", ns, "verb", verb, "from", from, "to", to, "class", cls, "reasons", list());
        r.put("sig", m("alg", "ed25519", "kid", "reg-1", "value", Issue.signBody(REG, ActionRegistry.EVOLUTION_DOMAIN, r)));
        return r;
    }

    /** A principal-signed re-approval over exactly these members. */
    static Map<String, Object> reapproval(Map<String, Object> body) {
        Map<String, Object> r = new LinkedHashMap<>(body);
        r.put("sig", m("alg", "ed25519", "value", Issue.signBody(PRINCIPAL, ActionRegistry.REAPPROVAL_DOMAIN, body)));
        return r;
    }

    static Map<String, Object> rapBody(String diff) { return m("v", 1, "kind", "pca-reapproval", "grant", GID, "verb", VERB, "diff", diff); }

    static final String P = d("pinned"), X = d("x"), Y = d("y"), Z = d("z"), ROOT = d("root");

    static Map<String, Object> pinIn(String presented, Object records, Object reapprovals, boolean withReapprovals) {
        Map<String, Object> i = m(
            "pin", m("pack", m("ns", NS, "root", ROOT), "defs", m(VERB, P), "on_new_action", "deny"),
            "doc", m("pack", m("ns", NS, "root", ROOT), "verbs", list(m("verb", VERB, "def", presented))),
            "verb", VERB, "keys", keys(), "grant", m("id", GID, "issuer", PRINCIPAL.id()));
        if (records != null) i.put("records", records);
        if (withReapprovals) i.put("reapprovals", reapprovals);
        return i;
    }

    static Map<String, Object> deny(String code, String reason, String needs) {
        Map<String, Object> o = m("ok", false, "code", code, "escalate", false, "reason", reason);
        if (needs != null) o.put("needs_reapproval", needs);
        return o;
    }

    static final Map<String, Object> CHAIN = m("ok", true, "via", "chain");
    static final Map<String, Object> NO_CHAIN = deny("def_changed", "the definition differs from the pinned digest and no signed evolution record chains to it", null);
    static Map<String, Object> widened(String needs) {
        return deny("def_changed", "the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve", needs);
    }
    static Map<String, Object> badPin(String why) { return deny("bad_pin", "pin evaluation error (fail closed): " + why, null); }

    // ---- decidePin ------------------------------------------------------------------------------------------------------------

    @Test void pinChainAndRecordFilters() {
        assertEquals(CHAIN, ActionRegistry.decidePin(pinIn(X, list(rec(NS, VERB, P, X, "equal")), null, false)));
        assertEquals(CHAIN, ActionRegistry.decidePin(pinIn(X, list(rec(NS, VERB, P, X, "narrow")), null, false)));
        // a validly signed step of another namespace or verb never moves the pin
        assertEquals(NO_CHAIN, ActionRegistry.decidePin(pinIn(X, list(rec("other", VERB, P, X, "equal")), null, false)));
        assertEquals(NO_CHAIN, ActionRegistry.decidePin(pinIn(X, list(rec(NS, "stripe.other", P, X, "equal")), null, false)));
        // an unverifiable record is skipped
        Map<String, Object> forged = rec(NS, VERB, P, X, "equal");
        forged.put("class", "narrow");
        assertEquals(NO_CHAIN, ActionRegistry.decidePin(pinIn(X, list(forged), null, false)));
        // added / removed records are skipped before re-approvals are read (a non-array re-approval list is never touched)
        assertEquals(NO_CHAIN, ActionRegistry.decidePin(pinIn(X, list(rec(NS, VERB, null, X, "added")), "x", true)));
        assertEquals(NO_CHAIN, ActionRegistry.decidePin(pinIn(X, list(rec(NS, VERB, P, null, "removed")), "x", true)));
        // keys absent: nothing verifies
        Map<String, Object> noKeys = pinIn(X, list(rec(NS, VERB, P, X, "equal")), null, false);
        noKeys.remove("keys");
        assertEquals(NO_CHAIN, ActionRegistry.decidePin(noKeys));
    }

    @Test void pinRecordsShape() {
        assertEquals(NO_CHAIN, ActionRegistry.decidePin(pinIn(X, null, null, false)));
        assertEquals(NO_CHAIN, ActionRegistry.decidePin(pinIn(X, "abc", null, false)));   // a string iterates as characters
        assertEquals(NO_CHAIN, ActionRegistry.decidePin(pinIn(X, list(), null, false)));
        assertEquals(badPin("records is not an array"), ActionRegistry.decidePin(pinIn(X, 5, null, false)));
        assertEquals(badPin("records is not an array"), ActionRegistry.decidePin(pinIn(X, m("a", 1), null, false)));
    }

    @Test void pinReapprovals() {
        Map<String, Object> w = rec(NS, VERB, P, X, "widen");
        String diff = ActionRegistry.evolutionDiffDigest(w);
        assertEquals(widened(diff), ActionRegistry.decidePin(pinIn(X, list(w), null, false)));
        assertEquals(widened(diff), ActionRegistry.decidePin(pinIn(X, list(w), null, true)));
        assertEquals(widened(diff), ActionRegistry.decidePin(pinIn(X, list(w), list(), true)));
        assertEquals(badPin("reapprovals is not an array"), ActionRegistry.decidePin(pinIn(X, list(w), "x", true)));
        assertEquals(badPin("reapprovals is not an array"), ActionRegistry.decidePin(pinIn(X, list(w), 7, true)));
        // a free step never reads the re-approvals
        assertEquals(CHAIN, ActionRegistry.decidePin(pinIn(X, list(rec(NS, VERB, P, X, "equal")), "x", true)));
        assertEquals(CHAIN, ActionRegistry.decidePin(pinIn(X, list(w), list(reapproval(rapBody(diff))), true)));
        assertEquals(CHAIN, ActionRegistry.decidePin(pinIn(X, list(w), list("junk", reapproval(rapBody(d("other"))), reapproval(rapBody(diff))), true)));
        assertEquals(widened(diff), ActionRegistry.decidePin(pinIn(X, list(w), list(reapproval(rapBody(d("other")))), true)));
    }

    /**
     * P -> X (widen, d1), P -> Y (equal), X -> Z (equal), Y -> Z (widen, d2). No usable path reaches Z; breadth first, Z is
     * first reached through X, so the step to re-approve is P -> X (d1), not Y -> Z (d2).
     */
    @Test void pinFirstBlockedStepOfTheBreadthFirstPath() {
        Map<String, Object> px = rec(NS, VERB, P, X, "widen"), py = rec(NS, VERB, P, Y, "equal"), xz = rec(NS, VERB, X, Z, "equal"), yz = rec(NS, VERB, Y, Z, "widen");
        String d1 = ActionRegistry.evolutionDiffDigest(px), d2 = ActionRegistry.evolutionDiffDigest(yz);
        assertNotEquals(d1, d2);
        assertEquals(widened(d1), ActionRegistry.decidePin(pinIn(Z, list(px, py, xz, yz), null, false)));
        // a cycle back to the pinned digest does not disturb the walk
        assertEquals(widened(d1), ActionRegistry.decidePin(pinIn(Z, list(px, py, xz, yz, rec(NS, VERB, X, P, "equal"), rec(NS, VERB, Z, P, "equal")), null, false)));
        // Y -> Z approved: the usable path P -> Y -> Z exists
        assertEquals(CHAIN, ActionRegistry.decidePin(pinIn(Z, list(px, py, xz, yz), list(reapproval(rapBody(d2))), true)));
        // two blocked steps on the only path: the one nearest the pinned digest is named
        Map<String, Object> xz2 = rec(NS, VERB, X, Z, "widen");
        assertEquals(widened(d1), ActionRegistry.decidePin(pinIn(Z, list(px, xz2), null, false)));
    }

    @Test void pinEvaluationErrorKeepsTheMessage() {
        Map<String, Object> i = pinIn(X, list(rec(NS, VERB, P, X, "widen")), null, false);
        i.put("grant", "not an object");
        Map<String, Object> r = ActionRegistry.decidePin(i);
        assertEquals("bad_pin", r.get("code"));
        assertTrue(((String) r.get("reason")).startsWith("pin evaluation error (fail closed): "));
        assertNotEquals("pin evaluation error (fail closed): null", r.get("reason"));
    }

    // ---- registry signature ---------------------------------------------------------------------------------------------------

    static final Map<String, Object> BODY = m("x", "y");
    static Map<String, Object> sig(Object kid) { return m("alg", "ed25519", "kid", kid, "value", Issue.signBody(REG, "dom", BODY)); }
    static List<Object> keyWithKid(Object kid) { return list(m("kid", kid, "alg", "ed25519", "pk", REG.id())); }

    @Test void registryKidEquality() {
        assertNull(ActionRegistry.verifyRegistrySig("dom", BODY, sig("reg-1"), keyWithKid("reg-1")));
        // numbers compare by value, not by representation
        assertNull(ActionRegistry.verifyRegistrySig("dom", BODY, sig(new Json.Num("1.0")), keyWithKid(1)));
        assertNull(ActionRegistry.verifyRegistrySig("dom", BODY, sig(1), keyWithKid(new Json.Num("1"))));
        assertNull(ActionRegistry.verifyRegistrySig("dom", BODY, sig(true), keyWithKid(true)));
        assertEquals("no registry key with kid '2'", ActionRegistry.verifyRegistrySig("dom", BODY, sig(2), keyWithKid(1)));
        assertEquals("no registry key with kid '1'", ActionRegistry.verifyRegistrySig("dom", BODY, sig(1), keyWithKid(m())));
        assertEquals("no registry key with kid '1'", ActionRegistry.verifyRegistrySig("dom", BODY, sig(1), keyWithKid("1")));
        assertEquals("no registry key with kid '1'", ActionRegistry.verifyRegistrySig("dom", BODY, sig(1), keyWithKid(true)));
        assertEquals("no registry key with kid '[1]'", ActionRegistry.verifyRegistrySig("dom", BODY, sig(list(1)), keyWithKid(1)));
        assertEquals("no registry key with kid 'true'", ActionRegistry.verifyRegistrySig("dom", BODY, sig(true), keyWithKid(1)));
        assertEquals("no registry key with kid 'true'", ActionRegistry.verifyRegistrySig("dom", BODY, sig(true), keyWithKid("true")));
        assertEquals("no registry key with kid 'null'", ActionRegistry.verifyRegistrySig("dom", BODY, sig(null), keyWithKid("reg-1")));
        Map<String, Object> noKid = sig("reg-1");
        noKid.remove("kid");
        assertEquals("no registry key with kid 'undefined'", ActionRegistry.verifyRegistrySig("dom", BODY, noKid, keyWithKid("reg-1")));
    }

    @Test void registryEvaluationErrorKeepsTheMessage() {
        Map<String, Object> hostile = new LinkedHashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("boom"); }
        };
        assertEquals("verification error: boom", ActionRegistry.verifyRegistrySig("dom", BODY, hostile, keys()));
    }

    // ---- evolution records ----------------------------------------------------------------------------------------------------

    @Test void evolutionRecordNullMember() {
        Map<String, Object> r = rec(NS, VERB, P, X, "equal");
        assertNull(ActionRegistry.evolutionRecordError(r, true));
        assertNull(ActionRegistry.verifyEvolutionRecord(r, keys()));
        Map<String, Object> top = new LinkedHashMap<>(r);
        top.put(null, 1);
        assertEquals("evolution record: unknown member 'null'", ActionRegistry.evolutionRecordError(top, true));
        Map<String, Object> unsigned = without(r, "sig");
        assertNull(ActionRegistry.evolutionRecordError(unsigned, false));
        unsigned.put(null, 1);
        assertEquals("evolution record: unknown member 'null'", ActionRegistry.evolutionRecordError(unsigned, false));
        Map<String, Object> s = new LinkedHashMap<>(r);
        Map<String, Object> sg = new LinkedHashMap<>(ActionRegistryRestKillTest.<Map<String, Object>>cast(r.get("sig")));
        sg.put(null, "x");
        s.put("sig", sg);
        assertEquals("evolution record: bad sig", ActionRegistry.evolutionRecordError(s, true));
    }

    @SuppressWarnings("unchecked") static <T> T cast(Object o) { return (T) o; }

    @Test void evolutionDiffDigestNeedsEveryMember() {
        Map<String, Object> r = without(rec(NS, VERB, P, X, "equal"), "sig");
        assertNotNull(ActionRegistry.evolutionDiffDigest(r));
        for (String k : new String[] {"ns", "verb", "from", "to", "class", "reasons"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ActionRegistry.evolutionDiffDigest(without(r, k)));
            assertEquals("record member missing: " + k, e.getMessage());
        }
    }

    // ---- re-approvals ---------------------------------------------------------------------------------------------------------

    static boolean rap(Object r) { return ActionRegistry.reapprovalValid(r, GID, PRINCIPAL.id(), VERB, X); }

    @Test void reapprovalEveryMember() {
        assertTrue(rap(reapproval(rapBody(X))));
        // each member wrong, yet validly signed over exactly that body
        assertFalse(rap(reapproval(m("v", 2, "kind", "pca-reapproval", "grant", GID, "verb", VERB, "diff", X))));
        assertFalse(rap(reapproval(m("v", 1, "kind", "pca-other", "grant", GID, "verb", VERB, "diff", X))));
        assertFalse(rap(reapproval(m("v", 1, "kind", "pca-reapproval", "grant", "other", "verb", VERB, "diff", X))));
        assertFalse(rap(reapproval(m("v", 1, "kind", "pca-reapproval", "grant", GID, "verb", "stripe.other", "diff", X))));
        assertFalse(rap(reapproval(m("v", 1, "kind", "pca-reapproval", "grant", GID, "verb", VERB, "diff", Y))));
        Map<String, Object> extra = rapBody(X);
        extra.put("note", "x");
        assertFalse(rap(reapproval(extra)));
        Map<String, Object> nullKey = new LinkedHashMap<>(reapproval(rapBody(X)));
        nullKey.put(null, 1);
        assertFalse(rap(nullKey));
        // signed by someone else
        Map<String, Object> other = rapBody(X);
        other.put("sig", m("alg", "ed25519", "value", Issue.signBody(REG, ActionRegistry.REAPPROVAL_DOMAIN, rapBody(X))));
        assertFalse(rap(other));
    }

    static Map<String, Object> withSig(Object s) { Map<String, Object> r = rapBody(X); r.put("sig", s); return r; }

    @Test void reapprovalSignatureMember() {
        String value = Issue.signBody(PRINCIPAL, ActionRegistry.REAPPROVAL_DOMAIN, rapBody(X));
        assertTrue(rap(withSig(m("alg", "ed25519", "value", value))));
        Map<String, Object> nk = m("alg", "ed25519", "value", value);
        nk.put(null, "x");
        assertFalse(rap(withSig(nk)));
        assertFalse(rap(withSig(m("alg", "ed25519", "value", value, "kid", "k"))));
        assertFalse(rap(withSig(m("alg", "ml-dsa-65", "value", value))));
        assertFalse(rap(withSig(m("value", value))));
        assertFalse(rap(withSig(m("alg", "ed25519", "value", 5))));
        assertFalse(rap(withSig(m("alg", "ed25519"))));
        assertFalse(rap(rapBody(X)));            // no sig
        assertFalse(rap(withSig(null)));
        assertFalse(rap(withSig("sig")));
        assertFalse(rap(withSig(list(value))));
        assertFalse(rap("reapproval"));
        assertFalse(rap(null));
        assertFalse(rap(list(rapBody(X))));
    }

    @Test void reapprovalIssuerAndUnhashableBody() {
        Map<String, Object> ok = reapproval(rapBody(X));
        assertFalse(ActionRegistry.reapprovalValid(ok, GID, 5, VERB, X));
        assertFalse(ActionRegistry.reapprovalValid(ok, GID, null, VERB, X));
        assertFalse(ActionRegistry.reapprovalValid(ok, GID, REG.id(), VERB, X));
        // a lone surrogate does not canonicalize: the signed message cannot be built, false (never a throw, never true)
        String lone = "\uD800";
        Map<String, Object> b = m("v", 1, "kind", "pca-reapproval", "grant", lone, "verb", VERB, "diff", X);
        b.put("sig", m("alg", "ed25519", "value", Issue.signBody(PRINCIPAL, ActionRegistry.REAPPROVAL_DOMAIN, m("x", 1))));
        assertFalse(ActionRegistry.reapprovalValid(b, lone, PRINCIPAL.id(), VERB, X));
    }

    // ---- the pin shape --------------------------------------------------------------------------------------------------------

    @Test void actionPinNullMember() {
        Map<String, Object> pin = m("pack", m("ns", NS, "root", ROOT), "defs", m(VERB, P), "on_new_action", "deny", "max_esc", 2, "preauth_esc", 1, "caveats", list("amount_cap"));
        assertNull(ActionRegistry.actionPinError(pin));
        Map<String, Object> top = new LinkedHashMap<>(pin);
        top.put(null, 1);
        assertEquals("actions: unknown member 'null'", ActionRegistry.actionPinError(top));
        Map<String, Object> pk = m("ns", NS, "root", ROOT);
        pk.put(null, 1);
        Map<String, Object> inner = new LinkedHashMap<>(pin);
        inner.put("pack", pk);
        assertEquals("actions.pack must be {ns, root}", ActionRegistry.actionPinError(inner));
    }

    // ---- versions -------------------------------------------------------------------------------------------------------------

    @Test void compareVersionsNamesTheBadOne() {
        assertEquals("'1.0' is not MAJOR.MINOR.PATCH", assertThrows(Actions.ActionKitError.class, () -> ActionRegistry.compareVersions("1.0", "1.0.0")).getMessage());
        assertEquals("'1.0' is not MAJOR.MINOR.PATCH", assertThrows(Actions.ActionKitError.class, () -> ActionRegistry.compareVersions("1.0.0", "1.0")).getMessage());
        assertEquals("'a' is not MAJOR.MINOR.PATCH", assertThrows(Actions.ActionKitError.class, () -> ActionRegistry.compareVersions("a", "b")).getMessage());
        assertEquals("bad_version", assertThrows(Actions.ActionKitError.class, () -> ActionRegistry.compareVersions("1.0.0", "x")).code);
        assertEquals(0, ActionRegistry.compareVersions("1.2.3", "1.2.3"));
        assertTrue(ActionRegistry.compareVersions("1.2.3", "1.10.0") < 0);
        assertTrue(ActionRegistry.compareVersions("2.0.0", "1.9.9") > 0);
    }

    // ---- pack shape -----------------------------------------------------------------------------------------------------------

    static Map<String, Object> shardedPack(boolean signed) {
        Map<String, Object> p = m("v", 1, "kind", "pca-action-pack", "ns", NS, "version", "1.0.0", "stability", "stable",
            "traits_digest", ROOT, "roles_digest", ROOT, "rules_digest", ROOT, "root", ROOT,
            "defs", m("shards", list(m("name", "a", "digest", ROOT, "uri", "https://x/a"))),
            "source", m("kind", "openapi", "uri", "https://x", "spec_digest", "s", "licence", "MIT", "licence_notes", ""),
            "prev", null, "evolution", list());
        if (signed) p.put("sig", m("alg", "ed25519", "kid", "reg-1", "value", "v"));
        return p;
    }

    static Map<String, Object> withShard(Map<String, Object> p, Map<String, Object> ref) {
        Map<String, Object> o = new LinkedHashMap<>(p);
        o.put("defs", m("shards", list(ref)));
        return o;
    }

    @Test void packShapeNullMembers() {
        for (boolean signed : new boolean[] {false, true}) {
            Map<String, Object> p = shardedPack(signed);
            assertNull(ActionRegistry.packShapeError(p, signed));
            Map<String, Object> top = new LinkedHashMap<>(p);
            top.put(null, 1);
            assertEquals("pack: unknown member 'null'", ActionRegistry.packShapeError(top, signed));
            Map<String, Object> src = new LinkedHashMap<>(p);
            Map<String, Object> s = new LinkedHashMap<>(ActionRegistryRestKillTest.<Map<String, Object>>cast(p.get("source")));
            s.put(null, "x");
            src.put("source", s);
            assertEquals("pack: source must be {kind, uri, spec_digest, licence, licence_notes}", ActionRegistry.packShapeError(src, signed));
            Map<String, Object> ref = m("name", "a", "digest", ROOT, "uri", "https://x/a");
            ref.put(null, "x");
            assertEquals("pack: bad shard ref", ActionRegistry.packShapeError(withShard(p, ref), signed));
        }
        Map<String, Object> p = shardedPack(true);
        Map<String, Object> sg = m("alg", "ed25519", "kid", "reg-1", "value", "v");
        sg.put(null, "x");
        p.put("sig", sg);
        assertEquals("pack: bad sig", ActionRegistry.packShapeError(p, true));
    }

    @Test void packShardDigestAndUri() {
        Map<String, Object> p = shardedPack(false);
        String bad = "pack: bad shard digest or uri";
        assertEquals(bad, ActionRegistry.packShapeError(withShard(p, m("name", "a", "digest", "short", "uri", "https://x/a")), false));
        assertEquals(bad, ActionRegistry.packShapeError(withShard(p, m("name", "a", "uri", "https://x/a")), false));
        assertEquals(bad, ActionRegistry.packShapeError(withShard(p, m("name", "a", "digest", ROOT, "uri", 5)), false));
        assertEquals(bad, ActionRegistry.packShapeError(withShard(p, m("name", "a", "digest", ROOT)), false));
        assertEquals(bad, ActionRegistry.packShapeError(withShard(p, m("name", "a", "digest", ROOT, "uri", "")), false));
        assertEquals(bad, ActionRegistry.packShapeError(withShard(p, m("name", "a", "digest", ROOT, "uri", "u".repeat(2049))), false));
        assertNull(ActionRegistry.packShapeError(withShard(p, m("name", "a", "digest", ROOT, "uri", "u".repeat(2048))), false));
        assertNull(ActionRegistry.packShapeError(withShard(p, m("name", "a", "digest", ROOT, "uri", "u")), false));
    }

    @Test void packDefsNamesTheForeignShard() {
        Map<String, Object> s = m("v", 1, "kind", "pca-action-pack-shard", "ns", "other", "version", "1.0.0", "name", "a", "defs", list());
        Map<String, Object> p = withShard(shardedPack(false), m("name", "a", "digest", ActionRegistry.shardDigest(s), "uri", "https://x/a"));
        Actions.ActionKitError e = assertThrows(Actions.ActionKitError.class, () -> ActionRegistry.packDefs(p, m("a", s)));
        assertEquals("bad_shard", e.code);
        assertEquals("shard 'a' is not a shard of this pack", e.getMessage());
    }

    // ---- signed packs ---------------------------------------------------------------------------------------------------------

    /** The oracle's honest pack p1 (real defs, honest vocabulary digests), without its evolution, re-signed by this test's key. */
    static Map<String, Object> p1() throws Exception {
        for (Map<String, Object> c : K05Oracle.of("k05-actionregistry", "verifyPack"))
            if ("verifyPack/p1".equals(c.get("name"))) {
                Map<String, Object> p = new LinkedHashMap<>(ActionRegistryRestKillTest.<Map<String, Object>>cast(((List<?>) c.get("args")).get(0)));
                p.put("evolution", list());
                return resign(p);
            }
        throw new AssertionError("verifyPack/p1 missing");
    }

    static Map<String, Object> resign(Map<String, Object> p) {
        Map<String, Object> body = without(p, "sig");
        Map<String, Object> o = new LinkedHashMap<>(body);
        o.put("sig", m("alg", "ed25519", "kid", "reg-1", "value", Issue.signBody(REG, ActionRegistry.PACK_SIG_DOMAIN, body)));
        return o;
    }

    static Map<String, Object> variant(Map<String, Object> p, Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>(p);
        for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        return resign(o);
    }

    @Test void verifyPackHonestAndEmpty() throws Exception {
        Map<String, Object> p = p1();
        Map<String, Object> ok = ActionRegistry.verifyPack(p, keys(), null);
        assertEquals(true, ok.get("ok"), String.valueOf(ok.get("reason")));
        assertEquals(ActionRegistry.packDigest(p), ok.get("digest"));
        assertEquals(3, ((List<?>) ok.get("defs")).size());
        // a sharded pack whose shards list no defs
        Map<String, Object> s = m("v", 1, "kind", "pca-action-pack-shard", "ns", NS, "version", "1.0.0", "name", "a", "defs", list());
        Map<String, Object> sh = variant(p, "defs", m("shards", list(m("name", "a", "digest", ActionRegistry.shardDigest(s), "uri", "https://x/a"))));
        assertEquals(m("ok", false, "reason", "the pack lists no defs or too many"), ActionRegistry.verifyPack(sh, keys(), m("a", s)));
    }

    @Test void defCountBounds() {
        assertFalse(ActionRegistry.defCountOk(0));
        assertTrue(ActionRegistry.defCountOk(1));
        assertTrue(ActionRegistry.defCountOk(1_000_000));
        assertFalse(ActionRegistry.defCountOk(1_000_001));
        assertFalse(ActionRegistry.defCountOk(-1));
    }

    /** An evolution list that cannot be iterated by verifyPack itself (shape and signature passes still read it). */
    static final class Hostile extends ArrayList<Object> {
        @Override public Iterator<Object> iterator() {
            StackTraceElement caller = new Throwable().getStackTrace()[1];
            if (caller.getClassName().equals(ActionRegistry.class.getName()) && caller.getMethodName().equals("verifyPack")) throw new IllegalStateException("boom");
            return super.iterator();
        }
    }

    @Test void verifyPackEvaluationError() throws Exception {
        Map<String, Object> p = variant(p1(), "evolution", new Hostile());
        assertEquals(m("ok", false, "reason", "pack verification error: boom"), ActionRegistry.verifyPack(p, keys(), null));
    }

    @Test void verifyPackProofTypes() {
        assertFalse(ActionRegistry.verifyPackProof(5, m("index", 0, "size", 1, "path", list()), ROOT));
        assertFalse(ActionRegistry.verifyPackProof(null, m("index", 0, "size", 1, "path", list()), ROOT));
        assertFalse(ActionRegistry.verifyPackProof(ROOT, "proof", ROOT));
        assertFalse(ActionRegistry.verifyPackProof(ROOT, list(), ROOT));
        assertFalse(ActionRegistry.verifyPackProof(ROOT, null, ROOT));
    }

    @Test void trackerRefusalsCarryEveryMember() throws Exception {
        Map<String, Object> base = p1();
        ActionRegistry.PackTracker t = new ActionRegistry.PackTracker(keys());
        assertEquals(m("ok", true, "status", "first"), t.accept(base, null));
        assertEquals(m("ok", true, "status", "same"), t.accept(base, null));
        assertEquals(m("ok", false, "code", "rollback", "reason", "older than the accepted version"), t.accept(variant(base, "version", "0.9.0"), null));
        assertEquals(m("ok", false, "code", "fork", "reason", "two different packs claim one version"), t.accept(variant(base, "stability", "beta"), null));
        assertEquals(m("ok", false, "code", "chain_gap", "reason", "prev does not name the accepted pack"), t.accept(variant(base, "version", "1.1.0", "prev", ROOT), null));
        assertEquals(m("ok", false, "code", "chain_gap", "reason", "prev does not name the accepted pack"), t.accept(variant(base, "version", "1.1.0"), null));
        Map<String, Object> next = variant(base, "version", "1.1.0", "prev", ActionRegistry.packDigest(base));
        assertEquals(m("ok", true, "status", "upgrade"), t.accept(next, null));
        // the accepted state moved: the old version is now a rollback, the next upgrade chains to the new digest
        assertEquals("rollback", t.accept(variant(base, "version", "1.0.5", "prev", ActionRegistry.packDigest(base)), null).get("code"));
        assertEquals(m("ok", true, "status", "upgrade"), t.accept(variant(base, "version", "1.2.0", "prev", ActionRegistry.packDigest(next)), null));
        Map<String, Object> bad = t.accept("pack", null);
        assertEquals(m("ok", false, "code", "bad_pack", "reason", "pack must be an object"), bad);
    }

    // ---- rule 22 --------------------------------------------------------------------------------------------------------------

    @Test void rule22IntegrityCodes() {
        assertNull(ActionRegistry.rule22Integrity(m("verbs", list())));
        assertEquals("schema_floor_forged", ActionRegistry.rule22Integrity(m("verbs", list(m("verb", "a.b")))));
        assertEquals("schema_floor_forged", ActionRegistry.rule22Integrity(m("verbs", list(m("verb", "a.b"))), null));
        assertEquals("unknown", ActionRegistry.integrityCode("something else"));
        assertEquals("unknown", ActionRegistry.integrityCode(""));
        for (String c : new String[] {"schema_floor_forged", "schema_traits_forged", "unknown_trait", "traits_digest_mismatch", "bad_registry"})
            assertEquals(c, ActionRegistry.integrityCode("x: " + c + ": y"));
    }

    static Map<String, Object> floors(int esc) {
        return m("risk", 2, "rev", "irreversible", "blast_ppm", 0, "esc", esc, "caveats", list("amount_cap"), "context", list("idempotency"), "prules", list());
    }
    static final Map<String, Object> GRANT = m("caveats", list("amount_cap"), "max_esc", 2, "preauth_esc", 2);
    static String r22(Map<String, Object> doc, Map<String, Object> grant, List<Object> ctx) { return ActionRegistry.rule22Decide(doc, VERB, grant, ctx); }

    @Test void rule22DecideFindsTheVerb() {
        List<Object> ctx = list("idempotency");
        assertEquals("allow", r22(m("verbs", list(m("verb", VERB, "floors", floors(0)))), GRANT, ctx));
        assertEquals("allow", r22(m("verbs", list(5, m("verb", VERB, "floors", floors(0)))), GRANT, ctx));
        assertEquals("allow", r22(m("verbs", list(null, m("verb", VERB, "floors", floors(0)))), GRANT, ctx));
        assertEquals("allow", r22(m("verbs", list(m("verb", "a.other", "floors", floors(3)), m("verb", VERB, "floors", floors(0)))), GRANT, ctx));
        assertEquals("deny", r22(m("verbs", list(m("verb", VERB, "floors", floors(3)))), GRANT, ctx));
        assertEquals("deny", r22(m("verbs", list(m("verb", "a.other", "floors", floors(0)))), GRANT, ctx));
        Map<String, Object> extra = floors(0);
        extra.put("x", 1);
        assertEquals("deny", r22(m("verbs", list(m("verb", VERB, "floors", extra))), GRANT, ctx));
    }

    @Test void rule22DecideGrantAndContext() {
        Map<String, Object> doc = m("verbs", list(m("verb", VERB, "floors", floors(0))));
        assertEquals("allow", r22(doc, m("caveats", list("junk", 5, "amount_cap"), "max_esc", 2, "preauth_esc", 2), list("junk", 7, "idempotency")));
        assertEquals("escalate", r22(doc, m("caveats", list("junk"), "max_esc", 2, "preauth_esc", 2), list("idempotency")));
        assertEquals("escalate", r22(doc, GRANT, list("junk")));
        assertEquals("escalate", r22(doc, GRANT, list()));
        // a null / non-array caveats or context denies, even where the rest would escalate
        assertEquals("deny", r22(doc, m("caveats", list("junk"), "max_esc", 2, "preauth_esc", 2), null));
        assertEquals("deny", r22(doc, m("max_esc", 2, "preauth_esc", 2), list("idempotency")));
        assertEquals("deny", r22(doc, m("caveats", "amount_cap", "max_esc", 2, "preauth_esc", 2), list("idempotency")));
    }
}
