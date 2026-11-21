package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for {@link PolicyAuthoring}: a differential test against the TS reference (shared oracle
 * test-data/k05-policyauthoring.json.gz, written by tools/pca-audit/k05-oracles/policyauthoring-oracle.mts): template
 * definitions, slot objects, references and overlays (every member deleted / retyped / at its limit, re-signed), a slot-value
 * grid per type and position (splice and matcher-injection rules), registries with overlays and bound parameter objects, and
 * random forbid-wins certificate tables with every single-field corruption. Exact reasons and exact policies; a reference
 * refusal that ends in "(fail closed)" (the reference threw on a malformed registry) only requires a Java refusal; a forbid
 * certificate whose table is not well typed only requires Java to reject it.
 */
public class K05PolicyAuthoringDiffTest {
    static final String MODULE = "k05-policyauthoring";

    static List<Map<String, Object>> cases(String fn) throws Exception {
        List<Map<String, Object>> cs = K05Oracle.of(MODULE, fn);
        assertFalse(cs.isEmpty(), "no " + fn + " cases");
        return cs;
    }

    @SuppressWarnings("unchecked")
    static List<Object> args(Map<String, Object> c) { return (List<Object>) c.get("args"); }

    static List<String> strs(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List) for (Object x : (List<?>) o) out.add((String) x);
        return out;
    }

    static void report(String fn, List<String> bad, int n) {
        if (!bad.isEmpty()) fail(fn + ": " + bad.size() + "/" + n + " mismatches:\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 60))));
    }

    interface StrFn { String apply(List<Object> a); }

    /** Reason (or null) against a reference string / {ok, reason} / {ok, policy[, overlays]} output. */
    static void reasons(String fn, StrFn f) throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases(fn);
        for (Map<String, Object> c : cs) {
            Object out = c.get("out");
            String want = out instanceof Map ? (String) IntentJs.get(out, "reason") : (String) out;
            String got;
            try {
                got = f.apply(args(c));
            } catch (RuntimeException e) {
                got = "threw " + e;
            }
            if (want != null && want.endsWith("(fail closed)")) {
                if (got == null || got.startsWith("threw ")) bad.add(c.get("name") + ": reference refused <" + want + ">, got <" + got + ">");
                continue;
            }
            if (!Objects.equals(want, got)) bad.add(c.get("name") + ": want <" + want + "> got <" + got + ">");
        }
        report(fn, bad, cs.size());
    }

    @Test void templateDef() throws Exception { reasons("templateDef", a -> PolicyAuthoring.templateDefError(a.get(0))); }

    @Test void tighten() throws Exception { reasons("tighten", a -> PolicyAuthoring.tightenOverlayError(a.get(0))); }

    @Test void templateRef() throws Exception { reasons("templateRef", a -> PolicyAuthoring.templateRefError(a.get(0))); }

    @Test void verifyTemplate() throws Exception { reasons("verifyTemplate", a -> PolicyAuthoring.verifyTemplate(a.get(0), strs(a.get(1)))); }

    @Test void verifyTighten() throws Exception { reasons("verifyTighten", a -> PolicyAuthoring.verifyTighten(a.get(0), strs(a.get(1)))); }

    interface ResFn { PolicyAuthoring.Result apply(List<Object> a); }

    static void results(String fn, ResFn f, boolean overlays) throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases(fn);
        for (Map<String, Object> c : cs) {
            Object out = c.get("out");
            String got;
            try {
                PolicyAuthoring.Result r = f.apply(args(c));
                got = r.policy == null ? "refused " + r.reason : (r.reason == null ? "" : "reason with policy ") + Json.canonicalize(r.policy) + (overlays ? " overlays " + r.overlays : "");
                if (r.policy == null && r.overlays != 0) got += " overlays " + r.overlays;
            } catch (RuntimeException e) {
                got = "threw " + e;
            }
            String want;
            if (Boolean.TRUE.equals(IntentJs.get(out, "ok"))) {
                want = Json.canonicalize(IntentJs.get(out, "policy")) + (overlays ? " overlays " + Json.canonicalize(IntentJs.get(out, "overlays")) : "");
            } else {
                String reason = (String) IntentJs.get(out, "reason");
                if (reason.endsWith("(fail closed)")) {
                    if (!got.startsWith("refused ") || got.equals("refused null")) bad.add(c.get("name") + ": reference refused <" + reason + ">, got <" + got + ">");
                    continue;
                }
                want = "refused " + reason;
            }
            if (!want.equals(got)) bad.add(c.get("name") + ": want <" + want + "> got <" + got + ">");
        }
        report(fn, bad, cs.size());
    }

    @Test void instantiate() throws Exception { results("instantiate", a -> PolicyAuthoring.instantiateTemplate(a.get(0), a.get(1)), false); }

    @Test void resolve() throws Exception { results("resolve", a -> PolicyAuthoring.resolveLink(a.get(0), a.get(1)), true); }

    @Test
    void forbidCertificate() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases("forbid");
        int typedTrue = 0, typedFalse = 0;
        for (Map<String, Object> c : cs) {
            Object out = c.get("out");
            boolean ok = Boolean.TRUE.equals(IntentJs.get(out, "ok")), typed = Boolean.TRUE.equals(IntentJs.get(out, "typed"));
            Object prec = args(c).get(1);
            boolean got;
            try {
                got = PolicyAuthoring.forbidCertificateConsistent(args(c).get(0), prec == null ? null : strs(prec));
            } catch (RuntimeException e) {
                bad.add(c.get("name") + ": threw " + e);
                continue;
            }
            boolean want = typed && ok; // an ill-typed table is refused by Java even where the reference's loose compare passes
            if (typed && ok) typedTrue++;
            if (typed && !ok) typedFalse++;
            if (got != want) bad.add(c.get("name") + ": want " + want + " got " + got + (typed ? "" : " (ill-typed)"));
        }
        assertTrue(typedTrue > 1000 && typedFalse > 1000, "certificate corpus too thin: " + typedTrue + " / " + typedFalse);
        report("forbid", bad, cs.size());
    }

    /** A row without a signer never reaches List.indexOf (an immutable precedence list refuses a null lookup). */
    @Test
    void unsignedRowWithImmutablePrecedence() {
        Object cert = Json.parseLenient("{\"v\":1,\"kind\":\"forbid-wins\",\"decision\":\"deny\",\"winner\":{\"kind\":\"forbid\",\"id\":\"y\"},\"shadowed\":[\"x\"],"
            + "\"clauses\":[{\"id\":\"x\",\"kind\":\"forbid\",\"value\":\"true\"},{\"id\":\"y\",\"kind\":\"forbid\",\"signer\":\"a\",\"value\":\"unknown\"}]}");
        assertTrue(PolicyAuthoring.forbidCertificateConsistent(cert, List.of("a")));
        Object byId = Json.parseLenient("{\"v\":1,\"kind\":\"forbid-wins\",\"decision\":\"deny\",\"winner\":{\"kind\":\"forbid\",\"id\":\"x\"},\"shadowed\":[\"y\"],"
            + "\"clauses\":[{\"id\":\"y\",\"kind\":\"forbid\",\"value\":\"true\"},{\"id\":\"x\",\"kind\":\"forbid\",\"value\":\"true\"}]}");
        assertTrue(PolicyAuthoring.forbidCertificateConsistent(byId, null));
        assertTrue(PolicyAuthoring.forbidCertificateConsistent(byId, List.of()));
    }
}
