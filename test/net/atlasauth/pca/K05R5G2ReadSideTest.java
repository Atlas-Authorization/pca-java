package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills (round 5, tag G2) for {@link ReadSide}: self-signed read grants and read receipts (keys generated here), so the
 * grade of a grant, the mask a mode gives, every validation of a receipt and the chain walk are pinned by exact results of the
 * reference (packages/pca/src/readside.ts gradeGrant / redactRead / readChainLabels / validReadGrantBody).
 */
public class K05R5G2ReadSideTest {

    static final K05R5G2MeshTest.Key P = new K05R5G2MeshTest.Key("g2-reader"), Q = new K05R5G2MeshTest.Key("g2-other-reader");
    static final String GD = Pca.b64(Pca.sha("g2-grant".getBytes(StandardCharsets.UTF_8)));
    static final String VD = Pca.b64(new byte[32]);
    static final String SALT = "0123456789abcdef";

    static Json.Num n(long v) { return IntentJs.ofLong(v); }
    static Map<String, Object> obj(Object... kv) { return MeshK05KillTest.obj(kv); }
    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }
    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static String sign(String domain, Object body, K05R5G2MeshTest.Key k) {
        return k.sign(Pca.concat(domain.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body)));
    }

    // ---- read grants ----

    static Map<String, Object> entry(String defMode) {
        return obj("verb", "orders.read", "resource_prefix", "/o/", "purposes", list("support"), "modes", obj(), "default_mode", defMode);
    }
    static Map<String, Object> readBody(String principal, String defMode) {
        return obj("v", n(1), "id", "g1", "principal", principal, "issued_at", n(1000), "expires_at", n(9000), "reads", list(entry(defMode)),
            "caps", obj(), "sinks", obj("sink1", obj("allow", list("pii"), "escalate", list())));
    }
    static Map<String, Object> grant(Map<String, Object> body, K05R5G2MeshTest.Key k) {
        return obj("body", body, "sig", sign(ReadSide.READ_GRANT_DOMAIN, body, k));
    }
    static Map<String, Object> grantMode(String mode) { return grant(readBody(P.pub, mode), P); }

    static Map<String, Object> schema() { return obj("fields", obj("card", "pii", "age", "pii"), "required", list()); }

    static ReadSide.Read red(Object grant, Object verb, Object resource, Object purpose, Object record, Object counts) {
        return ReadSide.redactRead(grant, P.pub, n(2000), verb, resource, purpose, schema(), record, obj(), SALT, counts);
    }
    static ReadSide.Read red(Object grant, Object record) { return red(grant, "orders.read", "/o/1", "support", record, obj()); }

    // ---- gradeGrant ----

    @Test void gradeGrantRefusesABadRequestWithAGradedResult() {
        Map<String, Object> g = grantMode("show");
        ReadSide.Graded a = ReadSide.gradeGrant(g, "x", n(2000));
        assertNotNull(a);
        assertEquals("bad_request", a.code);
        assertNull(a.body);
        ReadSide.Graded b = ReadSide.gradeGrant(g, P.pub, "x");
        assertNotNull(b);
        assertEquals("bad_request", b.code);
        ReadSide.Graded c = ReadSide.gradeGrant(g, P.pub, n(-1));
        assertNotNull(c);
        assertEquals("bad_request", c.code);
        ReadSide.Graded ok = ReadSide.gradeGrant(g, P.pub, n(2000));
        assertNull(ok.code);
        assertNotNull(ok.body);
    }

    @Test void gradeGrantNeedsExactlyBodyAndSig() {
        Map<String, Object> g = grantMode("show");
        Map<String, Object> extra = new LinkedHashMap<>(g);
        extra.put("extra", n(1));
        assertEquals("bad_grant", ReadSide.gradeGrant(extra, P.pub, n(2000)).code);
        Map<String, Object> noSig = new LinkedHashMap<>(g);
        noSig.remove("sig");
        assertEquals("bad_grant", ReadSide.gradeGrant(noSig, P.pub, n(2000)).code);
        Map<String, Object> other = new LinkedHashMap<>();
        other.put("body", g.get("body"));
        other.put("signature", g.get("sig"));
        assertEquals("bad_grant", ReadSide.gradeGrant(other, P.pub, n(2000)).code);
        assertEquals("bad_grant", ReadSide.gradeGrant("x", P.pub, n(2000)).code);
        assertEquals("bad_grant", ReadSide.gradeGrant(null, P.pub, n(2000)).code);
        assertEquals("bad_grant", ReadSide.gradeGrant(obj("body", "x", "sig", "y"), P.pub, n(2000)).code);
    }

    @Test void gradeGrantBindsTheBodysPrincipalToTheCaller() {
        // the body names another principal but is signed by the caller's key: the signature alone would verify
        Map<String, Object> body = readBody(Q.pub, "show");
        Map<String, Object> g = grant(body, P);
        assertEquals("bad_signature", ReadSide.gradeGrant(g, P.pub, n(2000)).code);
        assertEquals("bad_signature", ReadSide.gradeGrant(g, Q.pub, n(2000)).code);
        assertNull(ReadSide.gradeGrant(grant(body, Q), Q.pub, n(2000)).code);
        // times
        assertEquals("not_yet", ReadSide.gradeGrant(grantMode("show"), P.pub, n(999)).code);
        assertNull(ReadSide.gradeGrant(grantMode("show"), P.pub, n(1000)).code);
        assertNull(ReadSide.gradeGrant(grantMode("show"), P.pub, n(8999)).code);
        assertEquals("expired", ReadSide.gradeGrant(grantMode("show"), P.pub, n(9000)).code);
    }

    // ---- redactRead: the last4 mask is for basic-plane strings only ----

    @Test void last4MasksBasicPlaneStringsOnly() {
        Map<String, Object> g = grantMode("last4");
        ReadSide.Read r = red(g, obj("card", "abcdef"));
        assertEquals("allow", r.decision);
        assertEquals("****cdef", r.view.get("card"));
        assertEquals("masked", r.fields.get("card").action);
        // a basic-plane code point is shown, the first supplementary one drops the field
        assertEquals("****345\uFFFD", red(g, obj("card", "12345\uFFFD")).view.get("card"));
        ReadSide.Read sup = red(g, obj("card", "12345\uD800\uDC00"));
        assertEquals("allow", sup.decision);
        assertFalse(sup.view.containsKey("card"));
        assertEquals("dropped", sup.fields.get("card").action);
        ReadSide.Read sup2 = red(g, obj("card", "abc\uD800\uDC00defg"));
        assertFalse(sup2.view.containsKey("card"));
        assertEquals("dropped", sup2.fields.get("card").action);
        // four code points or fewer: nothing to mask with
        assertFalse(red(g, obj("card", "abcd")).view.containsKey("card"));
    }

    // ---- redactRead: request validation ----

    @Test void redactReadValidatesEachRequestMember() {
        Map<String, Object> g = grantMode("show");
        ReadSide.Read ok = red(g, obj("card", "abcdef"));
        assertEquals("allow", ok.decision);
        assertEquals("abcdef", ok.view.get("card"));
        String longResource = "/o/" + "x".repeat(510);
        assertEquals(513, longResource.length());
        assertEquals("allow", red(g, "orders.read", "/o/" + "x".repeat(509), "support", obj("card", "a"), obj()).decision);
        Object[][] bad = {
            {"", "/o/1", "support"}, {"orders.read", "", "support"}, {"orders.read", longResource, "support"},
            {"orders.read", "/o/1", "bad purpose"}, {"orders.read", "/o/1", ""}, {"orders.read", "/o/1", null},
            {null, "/o/1", "support"}, {"orders.read", null, "support"}, {n(5), "/o/1", "support"}, {"v".repeat(129), "/o/1", "support"},
        };
        for (Object[] row : bad) {
            ReadSide.Read r = red(g, row[0], row[1], row[2], obj("card", "a"), obj());
            assertEquals("deny", r.decision, Arrays.toString(row));
            assertEquals("bad_request", r.code, Arrays.toString(row));
        }
        // a verb the grant does not name is a scope refusal, not a malformed request
        assertEquals("no_read_scope", red(g, "orders.write", "/o/1", "support", obj("card", "a"), obj()).code);
    }

    @Test void redactReadCountsMustBeNonNegativeIntegers() {
        Map<String, Object> g = grantMode("show");
        assertEquals("allow", red(g, "orders.read", "/o/1", "support", obj("card", "a"), obj("pii", n(3))).decision);
        for (Object c : new Object[] {n(-1), "3", Boolean.TRUE, null, new Json.Num("1.5")}) {
            ReadSide.Read r = red(g, "orders.read", "/o/1", "support", obj("card", "a"), obj("pii", c));
            assertEquals("deny", r.decision, String.valueOf(c));
            assertEquals("bad_request", r.code, String.valueOf(c));
        }
        ReadSide.Read r = red(g, "orders.read", "/o/1", "support", obj("card", "a"), obj("Bad Label", n(1)));
        assertEquals("bad_request", r.code);
        assertEquals("bad_request", red(g, "orders.read", "/o/1", "support", obj("card", "a"), "x").code);
    }

    @Test void redactReadSchemaAndTightenMustBeWellFormed() {
        Map<String, Object> g = grantMode("show");
        Object[] schemas = {
            null, "x", obj(), obj("fields", obj()), obj("fields", "x", "required", list()), obj("fields", obj("card", "pii"), "required", "x"),
            obj("fields", obj("card", "pii"), "required", list("missing")), obj("fields", obj("card", "pii"), "required", list(n(1))),
            obj("fields", obj("bad name", "pii"), "required", list()), obj("fields", obj("card", "Bad"), "required", list()),
        };
        for (Object s : schemas) {
            ReadSide.Read r = ReadSide.redactRead(g, P.pub, n(2000), "orders.read", "/o/1", "support", s, obj("card", "a"), obj(), SALT, obj());
            assertEquals("bad_request", r.code, String.valueOf(s));
            assertEquals("deny", r.decision);
        }
        assertEquals("bad_request", ReadSide.redactRead(g, P.pub, n(2000), "orders.read", "/o/1", "support", schema(), obj("card", "a"), "x", SALT, obj()).code);
        assertEquals("bad_request", ReadSide.redactRead(g, P.pub, n(2000), "orders.read", "/o/1", "support", schema(), obj("card", "a"), obj("pii", "bogus"), SALT, obj()).code);
        assertEquals("bad_request", ReadSide.redactRead(g, P.pub, n(2000), "orders.read", "/o/1", "support", schema(), "x", obj(), SALT, obj()).code);
        assertEquals("bad_request", ReadSide.redactRead(g, P.pub, n(2000), "orders.read", "/o/1", "support", schema(), obj("card", "a"), obj(), null, obj()).code);
        assertEquals("bad_request", ReadSide.redactRead(g, P.pub, n(2000), "orders.read", "/o/1", "support", schema(), obj("card", "a"), obj(), "short", obj()).code);
        assertEquals("allow", ReadSide.redactRead(g, P.pub, n(2000), "orders.read", "/o/1", "support", schema(), obj("card", "a"), obj(), SALT, obj()).decision);
    }

    // ---- read-grant body shape ----

    @Test void readGrantBodyShape() {
        assertTrue(ReadSide.validReadGrantBody(readBody(P.pub, "show")));
        Map<String, Object> b = readBody(P.pub, "show");
        m(b.get("sinks")).put("bad key", obj("allow", list(), "escalate", list()));
        assertFalse(ReadSide.validReadGrantBody(b));
        b = readBody(P.pub, "show");
        m(b.get("sinks")).put("sink2", obj("allow", list(), "escalate", list(), "extra", list()));
        assertFalse(ReadSide.validReadGrantBody(b));
        b = readBody(P.pub, "show");
        m(b.get("sinks")).put("sink2", "x");
        assertFalse(ReadSide.validReadGrantBody(b));
        b = readBody(P.pub, "show");
        m(b.get("sinks")).put("sink2", obj("allow", list("b", "a"), "escalate", list()));
        assertFalse(ReadSide.validReadGrantBody(b));
        b = readBody(P.pub, "show");
        m(b.get("sinks")).put("sink2", obj("allow", list(), "escalate", list("b", "a")));
        assertFalse(ReadSide.validReadGrantBody(b));
        b = readBody(P.pub, "show");
        m(b.get("sinks")).put("sink2", obj("allow", list("pii"), "escalate", list("pii")));
        assertFalse(ReadSide.validReadGrantBody(b));
        b = readBody(P.pub, "show");
        m(b.get("sinks")).put("sink2", obj("allow", list("a"), "escalate", list("b")));
        assertTrue(ReadSide.validReadGrantBody(b));
        b = readBody(P.pub, "show");
        m(l(b.get("reads")).get(0)).put("extra", n(1));
        assertFalse(ReadSide.validReadGrantBody(b));
        b = readBody(P.pub, "show");
        l(b.get("reads")).set(0, "x");
        assertFalse(ReadSide.validReadGrantBody(b));
        assertFalse(ReadSide.validReadGrantBody("x"));
        assertFalse(ReadSide.validReadGrantBody(null));
    }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    // ---- read receipts ----

    static Map<String, Object> fld(Object cls, Object action) { return obj("class", cls, "action", action, "kind", null, "vd", VD); }

    static Map<String, Object> rcpt(K05R5G2MeshTest.Key k, String grantDigest, long seq, Object prev, Map<String, Object> over) {
        Map<String, Object> r = obj("v", n(1), "grant", grantDigest, "verb", "orders.read", "resource", "/o/1", "purpose", "support", "seq", n(seq), "prev", prev,
            "fields", obj("card", fld("pii", "shown")), "labels", list("pii"), "issued_at", n(1500), "signer", k.pub);
        r.putAll(over);
        Map<String, Object> body = new LinkedHashMap<>();
        for (String key : new String[] {"v", "grant", "verb", "resource", "purpose", "seq", "prev", "fields", "labels", "issued_at", "signer"}) body.put(key, r.get(key));
        r.put("sig", sign(ReadSide.READ_RECEIPT_DOMAIN, body, k));
        return r;
    }
    static Map<String, Object> rcpt(long seq, Object prev) { return rcpt(P, GD, seq, prev, obj()); }

    static String ch(ReadSide.Chain c) { return c.code == null ? "ok:" + c.labels : c.code + "@" + c.at; }
    static String chain(Object receipts) { return ch(ReadSide.readChainLabels(receipts, P.pub, GD, n(5000))); }
    static String one(Map<String, Object> r) { return chain(list(r)); }

    @Test void validReceiptChainsCarryTheirLabels() {
        assertEquals("ok:[]", chain(list()));
        Map<String, Object> r0 = rcpt(0, null);
        assertEquals("ok:[pii]", one(r0));
        Map<String, Object> r1 = rcpt(1, ReadSide.readReceiptRef(r0));
        assertEquals("ok:[pii]", chain(list(r0, r1)));
        Map<String, Object> r2 = rcpt(P, GD, 2, ReadSide.readReceiptRef(r1), obj("labels", list("a", "pii"), "fields", obj("card", fld("pii", "shown"), "x", fld("a", "masked"))));
        assertEquals("ok:[a, pii]", chain(list(r0, r1, r2)));
        // a dropped field carries no label; "unclassified" is a class like any other
        Map<String, Object> dropped = rcpt(P, GD, 0, null, obj("labels", list(), "fields", obj("card", fld("pii", "dropped"))));
        assertEquals("ok:[]", one(dropped));
        Map<String, Object> unclassified = rcpt(P, GD, 0, null, obj("labels", list("unclassified"), "fields", obj("card", fld("unclassified", "shown"))));
        assertEquals("ok:[unclassified]", one(unclassified));
        // issued exactly at now
        assertEquals("ok:[pii]", one(rcpt(P, GD, 0, null, obj("issued_at", n(5000)))));
        assertEquals("bad_receipt@0", one(rcpt(P, GD, 0, null, obj("issued_at", n(5001)))));
    }

    @Test void aChainIsRefusedAtTheFirstBrokenReceipt() {
        Map<String, Object> r0 = rcpt(0, null);
        String ref0 = ReadSide.readReceiptRef(r0);
        // a wrong or missing link
        assertEquals("bad_receipt@1", chain(list(r0, rcpt(1, Pca.b64(Pca.sha("other".getBytes(StandardCharsets.UTF_8)))))));
        assertEquals("bad_receipt@1", chain(list(r0, rcpt(1, null))));
        // a skipped or repeated sequence number, with the right link
        assertEquals("bad_receipt@1", chain(list(r0, rcpt(P, GD, 5, ref0, obj()))));
        assertEquals("bad_receipt@1", chain(list(r0, rcpt(P, GD, 0, ref0, obj()))));
        assertEquals("bad_receipt@0", chain(list(rcpt(P, GD, 1, ref0, obj()))));
        assertEquals("bad_receipt@0", chain(list(rcpt(P, GD, 0, ref0, obj()))));
        // the first receipt must not name a predecessor
        assertEquals("bad_receipt@0", chain(list(rcpt(P, GD, 0, Pca.b64(new byte[32]), obj()))));
        // a tampered signature
        Map<String, Object> bent = new LinkedHashMap<>(r0);
        bent.put("sig", sign(ReadSide.READ_RECEIPT_DOMAIN, obj("other", n(1)), P));
        assertEquals("bad_receipt@0", one(bent));
        Map<String, Object> bent1 = new LinkedHashMap<>(rcpt(1, ref0));
        bent1.put("sig", sign(ReadSide.READ_RECEIPT_DOMAIN, obj("other", n(1)), P));
        assertEquals("bad_receipt@1", chain(list(r0, bent1)));
        // the signature covers the labels
        Map<String, Object> relabeled = new LinkedHashMap<>(r0);
        relabeled.put("labels", list("zz"));
        assertEquals("bad_receipt@0", one(relabeled));
        // a label list that understates (or overstates) the non-dropped fields
        assertEquals("bad_receipt@0", one(rcpt(P, GD, 0, null, obj("labels", list()))));
        assertEquals("bad_receipt@0", one(rcpt(P, GD, 0, null, obj("labels", list("pii", "zz")))));
        // not a list / not a number
        assertEquals("bad_receipt@0", chain("x"));
        assertEquals("bad_receipt@0", chain(null));
        assertEquals("bad_receipt@0", chain(obj()));
        assertEquals("bad_receipt@0", ch(ReadSide.readChainLabels(list(r0), P.pub, GD, "x")));
        assertEquals("bad_receipt@0", ch(ReadSide.readChainLabels(list(r0), P.pub, GD, n(-1))));
        assertEquals("bad_receipt@0", ch(ReadSide.readChainLabels(list(), P.pub, GD, "x")));
        assertEquals("bad_receipt@0", chain(list("x")));
    }

    @Test void aReceiptMustBeIssuedByTheExpectedSignerForTheExpectedGrant() {
        Map<String, Object> r0 = rcpt(0, null);
        // a receipt that names another signer, signed by the expected key
        assertEquals("bad_receipt@0", one(rcpt(P, GD, 0, null, obj("signer", Q.pub))));
        // signed by another key under the expected signer's name
        Map<String, Object> forged = rcpt(Q, GD, 0, null, obj("signer", P.pub));
        assertEquals("bad_receipt@0", one(forged));
        // another grant
        String otherGrant = Pca.b64(Pca.sha("another-grant".getBytes(StandardCharsets.UTF_8)));
        assertEquals("bad_receipt@0", one(rcpt(P, otherGrant, 0, null, obj())));
        // a missing expected signer or digest never throws
        assertEquals("bad_receipt@0", ch(ReadSide.readChainLabels(list(r0), null, GD, n(5000))));
        assertEquals("bad_receipt@0", ch(ReadSide.readChainLabels(list(r0), n(5), GD, n(5000))));
        assertEquals("bad_receipt@0", ch(ReadSide.readChainLabels(list(r0), Q.pub, GD, n(5000))));
        assertEquals("bad_receipt@0", ch(ReadSide.readChainLabels(list(r0), P.pub, otherGrant, n(5000))));
    }

    @Test void aReceiptThatFailsAPrevCheckNeverReachesLaterReads() {
        // a predecessor that is not a canonical digest and an issued_at that is not a number: refused, never an exception
        Map<String, Object> junk = rcpt(P, GD, 0, "x", obj("issued_at", "bad"));
        assertEquals("bad_receipt@0", one(junk));
        Map<String, Object> junk2 = rcpt(P, GD, 0, n(5), obj("issued_at", new Json.Num("1.5")));
        assertEquals("bad_receipt@0", one(junk2));
        Map<String, Object> junk3 = rcpt(P, GD, 0, "x", obj("signer", P.pub, "issued_at", null));
        assertEquals("bad_receipt@0", one(junk3));
    }

    @Test void receiptMembersAreValidated() {
        String bad = "bad_receipt@0";
        String grantTwo = "g";
        // verb / resource / purpose: valid signatures, invalid members
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("verb", ""))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("verb", "v".repeat(129)))));
        assertEquals("ok:[pii]", one(rcpt(P, GD, 0, null, obj("verb", "v".repeat(128)))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("resource", ""))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("resource", "r".repeat(513)))));
        assertEquals("ok:[pii]", one(rcpt(P, GD, 0, null, obj("resource", "r".repeat(512)))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("purpose", "bad purpose"))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("purpose", ""))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("verb", null))));
        // a grant digest that is not canonical, matching the expected one
        assertEquals(bad, ch(ReadSide.readChainLabels(list(rcpt(P, grantTwo, 0, null, obj())), P.pub, grantTwo, n(5000))));
        // a version other than 1, a negative sequence number, issued_at
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("v", n(2)))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("issued_at", n(-1)))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("issued_at", "1500"))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("issued_at", null))));
        // extra and missing keys
        Map<String, Object> extra = new LinkedHashMap<>(rcpt(0, null));
        extra.put("extra", n(1));
        assertEquals(bad, one(extra));
        Map<String, Object> missing = new LinkedHashMap<>(rcpt(0, null));
        missing.remove("kind");
        missing.remove("sig");
        assertEquals(bad, one(missing));
    }

    @Test void receiptFieldsAndLabelsAreValidated() {
        String bad = "bad_receipt@0";
        // field names, classes, actions, kinds
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("bad name", fld("pii", "shown"))))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("card", "x")))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("card", null)))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("card", obj("class", "pii", "action", "shown", "kind", null))))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("card", obj("class", "pii", "action", "shown", "kind", null, "vd", VD, "x", n(1)))))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("card", fld(null, "shown"))))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("card", fld(n(5), "shown"))))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("card", fld("Bad", "dropped")), "labels", list()))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("card", fld("Bad", "shown")), "labels", list("Bad")))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("card", fld("pii", "bogus"))))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("card", fld("pii", null))))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("card", obj("class", "pii", "action", "shown", "kind", n(1), "vd", VD))))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", obj("card", obj("class", "pii", "action", "shown", "kind", null, "vd", "short"))))));
        assertEquals("ok:[pii]", one(rcpt(P, GD, 0, null, obj("fields", obj("card", obj("class", "pii", "action", "masked", "kind", "hash", "vd", VD))))));
        // fields not an object
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", null))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", "x"))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", list()))));
        // the sizes: 64 fields, 32 labels
        Map<String, Object> fields = new LinkedHashMap<>();
        List<Object> labels = new ArrayList<>();
        for (int i = 0; i < 33; i++) {
            fields.put(String.format("f%02d", i), fld(String.format("c%02d", i), "shown"));
            labels.add(String.format("c%02d", i));
        }
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", fields, "labels", labels))));
        Map<String, Object> f32 = new LinkedHashMap<>(fields);
        f32.remove("f32");
        assertEquals("ok:" + labels.subList(0, 32), one(rcpt(P, GD, 0, null, obj("fields", f32, "labels", new ArrayList<>(labels.subList(0, 32))))));
        Map<String, Object> many = new LinkedHashMap<>();
        for (int i = 0; i < 65; i++) many.put(String.format("f%02d", i), fld("pii", "dropped"));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("fields", many, "labels", list()))));
        many.remove("f64");
        assertEquals("ok:[]", one(rcpt(P, GD, 0, null, obj("fields", many, "labels", list()))));
        // labels: not a list, unsorted, duplicated
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("labels", "pii"))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("labels", null))));
        assertEquals(bad, one(rcpt(P, GD, 0, null, obj("labels", list("pii", "pii")))));
        // the signature member must be a string
        Map<String, Object> badSig = new LinkedHashMap<>(rcpt(0, null));
        badSig.put("sig", n(5));
        assertEquals(bad, one(badSig));
        badSig.put("sig", null);
        assertEquals(bad, one(badSig));
        // the signer member must be a canonical key; the expected signer names it
        Map<String, Object> shortSigner = rcpt(P, GD, 0, null, obj("signer", "short"));
        assertEquals(bad, ch(ReadSide.readChainLabels(list(shortSigner), "short", GD, n(5000))));
    }

    // ---- shared with the vault tests ----

    static Map<String, Object> recordOf(String json) { return m(Json.parseLenient(json)); }
}
