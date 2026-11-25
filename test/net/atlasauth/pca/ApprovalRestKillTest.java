package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** 0.5 mutation kills for {@link Approval}: every render refusal with its exact message, the flattening prefix, units and digests. */
public class ApprovalRestKillTest {
    @SuppressWarnings("unchecked") static Map<String, Object> M(Object o) { return (Map<String, Object>) o; }

    static Map<String, Object> m(Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        return o;
    }

    /** A fresh deep copy of the oracle's "renderApproval/min" definition (acme.pay: amount / currency / payee required). */
    static Map<String, Object> def() throws Exception {
        for (Map<String, Object> c : K05Oracle.of("k05-approval", "renderApproval"))
            if ("renderApproval/min".equals(c.get("name"))) return M(IntentJs.normalize(((List<?>) c.get("args")).get(0)));
        throw new AssertionError("renderApproval/min missing");
    }

    static Map<String, Object> base() { return m("amount", 1250, "currency", "EUR", "payee", "Bilbo"); }

    static Actions.ActionKitError refused(Map<String, Object> def, Object params) {
        return assertThrows(Actions.ActionKitError.class, () -> Approval.render(def, params, false));
    }

    static void refuses(String code, String msg, Map<String, Object> def, Object params) {
        Actions.ActionKitError e = refused(def, params);
        assertEquals(code, e.code);
        assertEquals(msg, e.getMessage());
    }

    @Test void renderRefusalMessages() throws Exception {
        Map<String, Object> d = def();
        refuses("render_bad_params", "params must be an object", d, "p");
        Map<String, Object> dotted = base();
        dotted.put("a.b", 1);
        refuses("render_bad_params", "the parameter key 'a.b' contains a dot", d, dotted);
        Map<String, Object> nested = base();
        nested.put("to", m("b.c", "x"));
        refuses("render_bad_params", "the parameter key 'b.c' contains a dot", d, nested);
        Map<String, Object> extra = base();
        extra.put("zzz", 1);
        refuses("render_undeclared_param", "'zzz' is not a parameter of acme.pay", d, extra);
        refuses("render_missing_param", "required parameter 'amount' of acme.pay is missing", d, m("currency", "EUR", "payee", "Bilbo"));
        refuses("render_missing_param", "required parameter 'payee' of acme.pay is missing", d, m("amount", 1, "currency", "EUR"));
        Map<String, Object> notInt = base();
        notInt.put("amount", "x");
        refuses("render_bad_value", "'amount' is not a integer in the canonical domain (no floats, no null, no lone surrogates)", d, notInt);
    }

    @Test void loneSurrogatesAreRefused() throws Exception {
        Map<String, Object> d = def();
        String msg = "'payee' is not a string in the canonical domain (no floats, no null, no lone surrogates)";
        for (String bad : new String[] {"a\uD800", "\uD800", "a\uDC00", "\uDC00b", "\uDC00\uD800"}) {
            Map<String, Object> p = base();
            p.put("payee", bad);
            refuses("render_bad_value", msg, d, p);
        }
        Map<String, Object> pair = base();
        pair.put("payee", "a😀b");
        assertNotNull(Approval.render(d, pair, false));
    }

    static Map<String, Object> field(Map<String, Object> render, String id) {
        for (Object f : (List<?>) render.get("fields")) if (id.equals(M(f).get("id"))) return M(f);
        return null;
    }

    @Test void anEmptyKeyAddsNoPrefix() throws Exception {
        Map<String, Object> p = base();
        p.put("", m("memo", "hi"));
        Map<String, Object> r = Approval.render(def(), p, false);
        assertEquals(m("id", "memo", "class", "param", "value", "hi"), field(r, "memo"));
        assertEquals(4, ((List<?>) r.get("fields")).size());
        // a nested key keeps its parent as prefix
        Map<String, Object> q = base();
        q.put("to", m("iban", "DE00"));
        assertEquals(m("id", "to.iban", "class", "param", "value", "DE00"), field(Approval.render(def(), q, false), "to.iban"));
    }

    @Test void unitAndTypeDefaults() throws Exception {
        Map<String, Object> odd = def();
        M(M(M(odd.get("params")).get("amount")).get("unit")).put("ccy", 5);
        refuses("render_unresolved_currency", "the currency of 'amount' is not a string", odd, base());
        Map<String, Object> weird = def();
        M(M(weird.get("params")).get("payee")).put("type", "weird");
        refuses("render_bad_value", "'payee' is not a weird in the canonical domain (no floats, no null, no lone surrogates)", weird, base());
    }

    // ---- shape, digests, words ------------------------------------------------------------------------------------------------

    static Map<String, Object> render() throws Exception { return Approval.render(def(), base(), true); }

    @Test void renderShapeUnits() throws Exception {
        Map<String, Object> r = render();
        assertNull(Approval.renderShapeError(r));
        for (Object kind : new Object[] {5, null, "money2", "volts"}) {
            Map<String, Object> x = M(IntentJs.normalize(r));
            M(M(((List<?>) x.get("fields")).get(1))).put("unit", m("kind", kind));
            assertEquals("unknown unit", Approval.renderShapeError(x), String.valueOf(kind));
        }
        for (String kind : new String[] {"count", "bytes", "duration", "ratio"}) {
            Map<String, Object> x = M(IntentJs.normalize(r));
            M(M(((List<?>) x.get("fields")).get(1))).put("unit", m("kind", kind));
            assertNull(Approval.renderShapeError(x), kind);
            M(M(((List<?>) x.get("fields")).get(1))).put("unit", m("kind", kind, "x", 1));
            assertEquals("unknown unit", Approval.renderShapeError(x), kind);
        }
        Map<String, Object> bad = M(IntentJs.normalize(r));
        bad.put("def_digest", 5);
        assertEquals("def_digest must be canonical base64url (32 bytes)", Approval.renderShapeError(bad));
        bad.put("def_digest", "short");
        assertEquals("def_digest must be canonical base64url (32 bytes)", Approval.renderShapeError(bad));
    }

    @Test void digestChallengeWords() throws Exception {
        assertEquals("approvalRenderDigest: render must be an object", assertThrows(IllegalArgumentException.class, () -> Approval.renderDigest("r")).getMessage());
        String rd = Approval.renderDigest(render());
        String ad = Pca.hashCanonical("action");
        String ch = Approval.challenge(ad, rd);
        java.security.MessageDigest h = java.security.MessageDigest.getInstance("SHA-256");
        h.update(Approval.CHALLENGE_DOMAIN.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        h.update(Pca.decodeB64uStrict(ad, 32));
        h.update(Pca.decodeB64uStrict(rd, 32));
        assertEquals(Pca.b64(h.digest()), ch);
        assertNotEquals(ch, Approval.challenge(rd, ad));
        String msg = "approvalChallenge: both digests must be canonical 32-byte values";
        for (Object[] bad : new Object[][] {{5, rd}, {ad, 5}, {null, rd}, {ad, "short"}, {"short", rd}})
            assertEquals(msg, assertThrows(IllegalArgumentException.class, () -> Approval.challenge(bad[0], bad[1])).getMessage());
        String w = Approval.bindingWords(rd);
        assertEquals(6, w.split("-").length);
        String wmsg = "bindingWords: render digest must be a canonical 32-byte value";
        for (Object bad : new Object[] {5, null, "short", list()})
            assertEquals(wmsg, assertThrows(IllegalArgumentException.class, () -> Approval.bindingWords(bad)).getMessage());
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(java.util.Arrays.asList(xs)); }
}
