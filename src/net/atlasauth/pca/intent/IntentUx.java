package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Catalog;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.CatValue;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumCell;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Question cards (a deterministic, structured form of a cell question: the sentence, one fact line per dimension, the verb's
 * reversibility, the three answers and the typed "partly" slots) and the parser that turns card input into the learner's answer.
 * Cards and inputs are JSON trees.
 */
public final class IntentUx {
    private IntentUx() {}

    private static final Pattern FIELD_RE = Pattern.compile("action\\.params\\.[a-z_][a-z0-9_]*|action\\.resource");

    private static String n(double d) { return AttestCommon.jsNumString(d); }

    private static Map<String, Object> fact(Dim d, int i) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("path", d.path);
        m.put("label", IntentRender.labelOf(d.path));
        if (d instanceof NumDim nd) {
            NumCell c = IntentOmega.numCells(nd).get(i);
            m.put("text", c.lo() == c.hi() ? "exactly " + n(c.lo()) : "any value from " + n(c.lo()) + " to " + n(c.hi()) + " (for example " + n(IntentOmega.numRep(nd, i)) + ")");
        } else {
            CatValue v = ((CatDim) d).values.get(i);
            m.put("text", v.kind().equals("exact") ? "\"" + v.value() + "\"" : v.kind().equals("prefix") ? "anything under \"" + v.value() + "\" not named elsewhere" : "any value not named anywhere in the grant or your request");
        }
        return m;
    }

    public static Map<String, Object> questionCard(Omega omega, String verb, int[] cell) { return questionCard(omega, verb, cell, Catalog.DEFAULT); }

    public static Map<String, Object> questionCard(Omega omega, String verb, int[] cell, Catalog catalog) {
        VerbSpace vs = IntentOmega.verbSpace(omega, verb);
        if (vs == null) throw new IllegalArgumentException("questionCard: no verb " + verb);
        List<Object> facts = new ArrayList<>();
        List<Object> partial = new ArrayList<>();
        for (int k = 0; k < vs.dims.size(); k++) {
            Dim d = vs.dims.get(k);
            facts.add(fact(d, cell[k]));
            Map<String, Object> slot = new LinkedHashMap<>();
            slot.put("path", d.path);
            if (d instanceof NumDim nd) {
                NumCell c = IntentOmega.numCells(nd).get(cell[k]);
                slot.put("kind", "num");
                slot.put("lo", c.lo());
                slot.put("hi", c.hi());
            } else {
                slot.put("kind", "cat");
                List<Object> opts = new ArrayList<>();
                for (CatValue v : ((CatDim) d).values) if (v.kind().equals("exact")) opts.add(v.value());
                slot.put("options", opts);
            }
            partial.add(slot);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", new net.atlasauth.pca.Json.Num("1"));
        body.put("verb", verb);
        List<Object> cl = new ArrayList<>();
        for (int x : cell) cl.add(new net.atlasauth.pca.Json.Num(String.valueOf(x)));
        body.put("cell", cl);
        body.put("sentence", IntentRender.renderQuestion(vs, cell, catalog));
        body.put("facts", facts);
        body.put("reversibility", vs.reversibility);
        body.put("answers", new ArrayList<Object>(List.of("yes", "no", "partly")));
        body.put("partial", partial);
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("d", "atlas-pca/intent-card/v1");
        h.put("c", IntentRuntime.jsonNums(body));
        Map<String, Object> card = new LinkedHashMap<>(body);
        card.put("digest", Pca.hashCanonical(h));
        return card;
    }

    private static Map<String, Object> res(Object answer) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("answer", answer);
        return m;
    }

    private static Map<String, Object> err(String e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("error", e);
        return m;
    }

    private static Map<String, Object> part(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** The distinct non-empty strings of {@code list} in first-seen order; throws when it is not an array (the reference calls .filter). */
    private static List<Object> namedValues(Object list) {
        if (!(list instanceof List)) throw new IllegalArgumentException("filter is not a function");
        Set<Object> out = new LinkedHashSet<>();
        for (Object x : (List<?>) list) if (x instanceof String && !((String) x).isEmpty()) out.add(x);
        return new ArrayList<>(out);
    }

    private static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    /** Turn the UI input into the learner's answer: {ok: true, answer} or {ok: false, error}. */
    public static Map<String, Object> parseCardAnswer(Object card, Object input) {
        if (!"partly".equals(get(input, "answer"))) return res("yes".equals(get(input, "answer")) ? 1.0 : 0.0);
        List<?> slots = IntentOmega.arr(get(card, "partial"));
        if (has(input, "newField")) {
            String nf = IntentRender.str(get(input, "newField"));
            if (!FIELD_RE.matcher(nf).matches()) return err("unknown field " + nf);
            for (Object s : slots) if (nf.equals(get(s, "path"))) return err(nf + " is already on the card; answer partly for it directly");
            List<Object> vals = namedValues(get(input, "notFor"));
            if (vals.isEmpty()) return err("name at least one value");
            List<Object> dvals = new ArrayList<>();
            for (Object v : vals) dvals.add(part("kind", "exact", "value", v));
            dvals.add(part("kind", "other", "value", IntentOmega.OTHER));
            Map<String, Object> a = part("kind", "partial", "path", nf, "newDim", part("kind", "cat", "path", nf, "values", dvals),
                "parts", new ArrayList<Object>(List.of(part("values", vals, "y", 0.0), part("other", true, "y", 1.0))));
            return res(a);
        }
        Object path = get(input, "path");
        Object slot = null;
        if (path instanceof String) for (Object s : slots) if (path.equals(get(s, "path"))) { slot = s; break; }
        if (slot == null) return err("the card has no field " + IntentRender.str(has(input, "path") ? path : IntentRender.UNDEF));
        String sp = (String) get(slot, "path");
        if ("num".equals(get(slot, "kind"))) {
            double lo = IntentOmega.dbl(get(slot, "lo")), hi = IntentOmega.dbl(get(slot, "hi"));
            if (has(input, "upTo")) {
                Object x = get(input, "upTo");
                if (!inRange(x, lo, hi) || IntentOmega.dbl(x) == hi) return err("upTo must be an integer in [" + n(lo) + ", " + n(hi - 1) + "]");
                double u = IntentOmega.dbl(x);
                return res(part("kind", "partial", "path", sp, "cuts", new ArrayList<Object>(List.of(u)),
                    "parts", new ArrayList<Object>(List.of(part("lo", lo, "hi", u, "y", 1.0), part("lo", u + 1, "hi", hi, "y", 0.0)))));
            }
            if (has(input, "from")) {
                Object x = get(input, "from");
                if (!inRange(x, lo, hi) || IntentOmega.dbl(x) == lo) return err("from must be an integer in [" + n(lo + 1) + ", " + n(hi) + "]");
                double f = IntentOmega.dbl(x);
                return res(part("kind", "partial", "path", sp, "cuts", new ArrayList<Object>(List.of(f)),
                    "parts", new ArrayList<Object>(List.of(part("lo", lo, "hi", f - 1, "y", 0.0), part("lo", f, "hi", hi, "y", 1.0)))));
            }
            if (has(input, "except")) {
                Object ex0 = get(input, "except");
                if (ex0 != null && !(ex0 instanceof List) && !(ex0 instanceof String)) throw new IllegalArgumentException("not iterable");
                List<Double> ex = new ArrayList<>();
                boolean allIn = true;
                if (ex0 instanceof List) {
                    Set<Double> seen = new LinkedHashSet<>();
                    for (Object x : (List<?>) ex0) {
                        if (!inRange(x, lo, hi)) allIn = false;
                        else seen.add(IntentOmega.dbl(x) + 0.0);
                    }
                    ex.addAll(seen);
                    ex.sort(Double::compare);
                } else allIn = false;
                if (ex0 instanceof List && ((List<?>) ex0).isEmpty() || ex0 == null || !allIn) return err("except values must be integers in [" + n(lo) + ", " + n(hi) + "]");
                List<Object> parts = new ArrayList<>();
                for (double x : ex) parts.add(part("lo", x, "hi", x, "y", 0.0));
                parts.add(part("lo", lo, "hi", hi, "y", 1.0));
                return res(part("kind", "partial", "path", sp, "cuts", new ArrayList<Object>(ex), "parts", parts));
            }
            return err("a numeric partly answer needs upTo, from or except");
        }
        if (!has(input, "notFor")) return err("a categorical partly answer needs notFor");
        List<Object> vals = namedValues(get(input, "notFor"));
        if (vals.isEmpty()) return err("name at least one value");
        return res(part("kind", "partial", "path", sp, "values", vals, "parts", new ArrayList<Object>(List.of(part("values", vals, "y", 0.0), part("other", true, "y", 1.0)))));
    }

    private static boolean inRange(Object x, double lo, double hi) {
        if (!IntentOmega.isNumber(x)) return false;
        double v = IntentOmega.dbl(x);
        return Double.isFinite(v) && v == Math.rint(v) && Double.doubleToRawLongBits(v) != Double.doubleToRawLongBits(-0.0) && v >= lo && v <= hi;
    }
}
