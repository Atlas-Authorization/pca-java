package net.atlasauth.pca.actions;

import java.io.StringReader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Json;
import org.snakeyaml.engine.v2.api.LoadSettings;
import org.snakeyaml.engine.v2.api.lowlevel.Parse;
import org.snakeyaml.engine.v2.common.ScalarStyle;
import org.snakeyaml.engine.v2.events.AliasEvent;
import org.snakeyaml.engine.v2.events.DocumentEndEvent;
import org.snakeyaml.engine.v2.events.DocumentStartEvent;
import org.snakeyaml.engine.v2.events.Event;
import org.snakeyaml.engine.v2.events.MappingEndEvent;
import org.snakeyaml.engine.v2.events.MappingStartEvent;
import org.snakeyaml.engine.v2.events.ScalarEvent;
import org.snakeyaml.engine.v2.events.SequenceEndEvent;
import org.snakeyaml.engine.v2.events.SequenceStartEvent;
import org.snakeyaml.engine.v2.exceptions.MarkedYamlEngineException;

/**
 * The authoring-file text loader: YAML 1.2 core schema or JSON text, with source positions. The syntax layer is SnakeYAML-engine's parser; only its
 * EVENT stream is used. Everything the reference decides about meaning is done here, so the result does not depend on the library's own resolver or
 * alias handling: the tree is built from events, plain scalars are resolved with the YAML 1.2 core schema (null, bool, int, 0o / 0x, float, .inf,
 * .nan; everything else a string), mapping keys are stringified the way JavaScript does, aliases are refused, "&lt;&lt;" is an ordinary key, and
 * positions are the 1-based start of each action and each param key.
 *
 * <p>Where this differs from the reference it is STRICTER (it refuses): an explicit tag other than !!str / !!map / !!seq, a complex (non-scalar)
 * mapping key, two keys that are equal once stringified, a bare carriage return used as a line break, more than one document. Syntax error wording and
 * the line/column of a syntax error are the parser's own.
 */
public final class ActionsText {
    private ActionsText() {}

    /** A syntax or policy refusal of the YAML front end (message plus 1-based position). */
    public static final class YamlLoadError extends RuntimeException {
        public final int line;
        public final int column;
        YamlLoadError(String message, int line, int column) { super(message); this.line = line; this.column = column; }
        YamlLoadError(String message) { this(message, 1, 1); }
    }

    private static final String STR_TAG = "tag:yaml.org,2002:str", MAP_TAG = "tag:yaml.org,2002:map", SEQ_TAG = "tag:yaml.org,2002:seq";
    private static final BigInteger SAFE = BigInteger.ONE.shiftLeft(53);
    private static final Pattern INT_RE = Pattern.compile("[-+]?[0-9]+"), OCT_RE = Pattern.compile("0o[0-7]+"), HEX_RE = Pattern.compile("0x[0-9a-fA-F]+"),
        FLOAT_RE = Pattern.compile("[-+]?(?:\\.[0-9]+|[0-9]+(?:\\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?"), INF_RE = Pattern.compile("[-+]?\\.(?:inf|Inf|INF)"),
        NAN_RE = Pattern.compile("\\.(?:nan|NaN|NAN)"), BARE_CR = Pattern.compile("\r(?!\n)");

    private static final class N {
        final String kind; // scalar | map | seq
        final int line, col;
        Object value;
        final List<N> seq = new ArrayList<>();
        final List<N[]> map = new ArrayList<>();
        N(String kind, int line, int col) { this.kind = kind; this.line = line; this.col = col; }
    }

    private static final class Pos {
        final int line, col;
        final Map<String, Object> params;
        Pos(int line, int col, Map<String, Object> params) { this.line = line; this.col = col; this.params = params; }
    }

    private static Object jsNumber(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) return d;
        return new Json.Num(d == 0.0 ? "0" : AttestCommon.jsNumString(d));
    }

    private static Object jsInt(String text, int radix) {
        boolean neg = text.startsWith("-");
        String digits = text.replaceFirst("^[+-]+", "");
        BigInteger n = new BigInteger(digits, radix);
        if (neg && n.signum() == 0) return jsNumber(-0.0);
        if (neg) n = n.negate();
        return n.abs().compareTo(SAFE) <= 0 ? new Json.Num(n.toString()) : jsNumber(n.doubleValue());
    }

    /** The YAML 1.2 core schema value of a plain scalar, as a JSON tree value (number, bool, null or string). */
    public static Object resolveCorePlain(String text) {
        if (text.isEmpty() || text.equals("~") || text.equals("null") || text.equals("Null") || text.equals("NULL")) return null;
        if (text.equals("true") || text.equals("True") || text.equals("TRUE")) return Boolean.TRUE;
        if (text.equals("false") || text.equals("False") || text.equals("FALSE")) return Boolean.FALSE;
        if (INT_RE.matcher(text).matches()) return jsInt(text, 10);
        if (OCT_RE.matcher(text).matches()) return jsInt(text.substring(2), 8);
        if (HEX_RE.matcher(text).matches()) return jsInt(text.substring(2), 16);
        if (INF_RE.matcher(text).matches()) return text.charAt(0) == '-' ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY;
        if (NAN_RE.matcher(text).matches()) return Double.NaN;
        if (FLOAT_RE.matcher(text).matches()) {
            double f = Double.parseDouble(text);
            boolean negZero = f == 0.0 && text.replaceFirst("^\\+", "").startsWith("-");
            return f == Math.floor(f) && Math.abs(f) <= 9007199254740992.0 && !negZero ? new Json.Num(Long.toString((long) f)) : jsNumber(f);
        }
        return text;
    }

    private static String jsKey(Object v) {
        if (v == null) return "null";
        if (v instanceof Boolean) return ((Boolean) v) ? "true" : "false";
        if (v instanceof Json.Num) return ((Json.Num) v).raw;
        if (v instanceof Double) { double d = (Double) v; return Double.isNaN(d) ? "NaN" : d > 0 ? "Infinity" : "-Infinity"; }
        return (String) v;
    }

    private static String tagOf(Optional<String> t) { return t.isPresent() && !t.get().isEmpty() ? t.get() : null; }

    private static int lineOf(Event e) { return e.getStartMark().isPresent() ? e.getStartMark().get().getLine() + 1 : 1; }

    private static int colOf(Event e) { return e.getStartMark().isPresent() ? e.getStartMark().get().getColumn() + 1 : 1; }

    private static final class Builder {
        final List<Event> events;
        final boolean strict;
        int pos = 0;

        Builder(List<Event> events, boolean strict) { this.events = events; this.strict = strict; }

        N node() {
            if (pos >= events.size()) throw new YamlLoadError("unexpected end of the event stream");
            Event ev = events.get(pos++);
            int line = lineOf(ev), col = colOf(ev);
            if (ev instanceof AliasEvent) throw new YamlLoadError("Alias resolution is disabled", line, col);
            String tag = ev instanceof ScalarEvent ? tagOf(((ScalarEvent) ev).getTag())
                : ev instanceof SequenceStartEvent ? tagOf(((SequenceStartEvent) ev).getTag())
                : ev instanceof MappingStartEvent ? tagOf(((MappingStartEvent) ev).getTag()) : null;
            if (tag != null && !tag.equals(STR_TAG) && !tag.equals(MAP_TAG) && !tag.equals(SEQ_TAG)) throw new YamlLoadError("Unresolved or unsupported tag: " + tag, line, col);
            if (ev instanceof ScalarEvent) {
                ScalarEvent se = (ScalarEvent) ev;
                N n = new N("scalar", line, col);
                n.value = se.getScalarStyle() == ScalarStyle.PLAIN && tag == null ? resolveCorePlain(se.getValue()) : se.getValue();
                return n;
            }
            if (ev instanceof SequenceStartEvent) {
                N n = new N("seq", line, col);
                while (pos < events.size() && !(events.get(pos) instanceof SequenceEndEvent)) n.seq.add(node());
                pos++;
                return n;
            }
            if (ev instanceof MappingStartEvent) {
                N n = new N("map", line, col);
                Set<String> seen = new HashSet<>();
                while (pos < events.size() && !(events.get(pos) instanceof MappingEndEvent)) {
                    N key = node();
                    N val = node();
                    if (strict) {
                        if (!key.kind.equals("scalar")) throw new YamlLoadError("complex mapping keys are not accepted", key.line, key.col);
                        if (!seen.add(jsKey(key.value))) throw new YamlLoadError("Map keys must be unique", key.line, key.col);
                    }
                    n.map.add(new N[] {key, val});
                }
                pos++;
                return n;
            }
            throw new YamlLoadError("unexpected parser event " + ev.getClass().getSimpleName(), line, col);
        }
    }

    private static N parseDocument(String text, boolean strict) {
        if (BARE_CR.matcher(text).find()) throw new YamlLoadError("bare carriage return is not accepted as a line break");
        List<Event> events = new ArrayList<>();
        try {
            for (;;) {
                events.clear();
                try {
                    for (Event e : new Parse(LoadSettings.builder().build()).parseReader(new StringReader(text))) events.add(e);
                    break;
                } catch (MarkedYamlEngineException e) {
                    // the YAML 1.2 line / paragraph separator escapes (\L, \P) are unknown to the engine: spell the one it stopped at with the numeric escape of that separator and parse again
                    String m = String.valueOf(e.getMessage());
                    boolean ls = m.contains("found unknown escape character L("), ps = m.contains("found unknown escape character P(");
                    if (!(ls || ps) || !e.getProblemMark().isPresent()) throw e;
                    int at = text.offsetByCodePoints(0, e.getProblemMark().get().getIndex());
                    if (at < 1 || at >= text.length() || text.charAt(at - 1) != '\\' || text.charAt(at) != (ls ? 'L' : 'P')) throw e;
                    text = text.substring(0, at - 1) + (ls ? "\\u2028" : "\\u2029") + text.substring(at + 1);
                }
            }
        } catch (MarkedYamlEngineException e) {
            int line = 1, col = 1;
            if (e.getProblemMark().isPresent()) { line = e.getProblemMark().get().getLine() + 1; col = e.getProblemMark().get().getColumn() + 1; }
            throw new YamlLoadError(String.valueOf(e.getMessage()), line, col);
        } catch (RuntimeException e) {
            throw new YamlLoadError(String.valueOf(e.getMessage()));
        }
        Builder b = new Builder(events, strict);
        int docs = 0;
        N root = null;
        while (b.pos < events.size()) {
            if (events.get(b.pos) instanceof DocumentStartEvent) {
                if (++docs > 1) throw new YamlLoadError("Source contains multiple documents; please use YAML.parseAllDocuments()");
                b.pos++;
                if (b.pos < events.size() && !(events.get(b.pos) instanceof DocumentEndEvent)) root = b.node();
            } else b.pos++;
        }
        return root;
    }

    private static Object toValue(N n) {
        if (n == null) return null;
        if (n.kind.equals("scalar")) return n.value;
        if (n.kind.equals("seq")) {
            List<Object> out = new ArrayList<>();
            for (N x : n.seq) out.add(toValue(x));
            return out;
        }
        Map<String, Object> o = new LinkedHashMap<>();
        for (N[] kv : n.map) {
            if (!kv[0].kind.equals("scalar")) throw new YamlLoadError("complex mapping keys are not accepted", kv[0].line, kv[0].col);
            o.put(jsKey(kv[0].value), toValue(kv[1]));
        }
        return o;
    }

    private static boolean isKey(N k, String name) { return k.kind.equals("scalar") && name.equals(k.value); }

    // per-entry positions of an authoring document (actions items and their params keys), by entry index; null when not a mapping
    private static List<Pos> positionsOf(N root) {
        if (root == null || !root.kind.equals("map")) return null;
        N actions = null;
        for (N[] kv : root.map) if (isKey(kv[0], "actions")) actions = kv[1];
        List<N> items;
        if (actions != null && actions.kind.equals("seq")) items = actions.seq;
        else { items = new ArrayList<>(); items.add(root); }
        List<Pos> res = new ArrayList<>();
        for (N it : items) {
            Map<String, Object> ps = new LinkedHashMap<>();
            if (it.kind.equals("map")) {
                N pm = null;
                for (N[] kv : it.map) if (isKey(kv[0], "params")) pm = kv[1];
                if (pm != null && pm.kind.equals("map"))
                    for (N[] kv : pm.map)
                        if (kv[0].kind.equals("scalar")) ps.put(kv[0].value == null ? "" : jsKey(kv[0].value), J.obj("line", J.n(kv[0].line), "column", J.n(kv[0].col)));
            }
            res.add(new Pos(it.line, it.col, ps));
        }
        return res;
    }

    private static Long indexOf(Object e) {
        if (!(e instanceof Map)) return null;
        Object ix = ((Map<?, ?>) e).get("index");
        if (!(ix instanceof Json.Num)) return null;
        try { return Long.parseLong(((Json.Num) ix).raw); } catch (NumberFormatException x) { return null; }
    }

    private static void attachPositions(Map<String, Object> res, List<Pos> pos) {
        List<Object> errors = J.a(res.get("errors"));
        Set<Long> failed = new HashSet<>();
        for (Object e : errors) { Long ix = indexOf(e); if (ix != null) failed.add(ix); }
        List<Integer> order = new ArrayList<>();
        for (int i = 0; i < pos.size(); i++) if (!failed.contains((long) i)) order.add(i);
        List<Object> defs = J.a(res.get("defs"));
        Map<String, Object> locs = J.m(res.get("locs"));
        for (int k = 0; k < defs.size(); k++) {
            if (k < order.size()) {
                Pos p = pos.get(order.get(k));
                locs.put((String) J.m(defs.get(k)).get("verb"), J.obj("line", J.n(p.line), "column", J.n(p.col), "params", p.params));
            }
        }
        for (Object e : errors) {
            Map<String, Object> em = J.m(e);
            Long ix = indexOf(e);
            if (ix != null) {
                if (ix >= 0 && ix < pos.size()) { em.put("line", J.n(pos.get((int) (long) ix).line)); em.put("column", J.n(pos.get((int) (long) ix).col)); }
            } else { em.put("line", J.n(1)); em.put("column", J.n(1)); }
        }
    }

    private static Map<String, Object> fail(String message, int line, int column) {
        return J.obj("defs", new ArrayList<Object>(), "notes", new ArrayList<Object>(),
            "errors", J.list(J.obj("message", message, "line", J.n(line), "column", J.n(column))),
            "locs", new LinkedHashMap<String, Object>(), "rules", new LinkedHashMap<String, Object>());
    }

    /**
     * Load an authoring file (YAML 1.2 core or JSON, {@code fmt} "yaml" or "json") with source positions. Input above
     * {@link ActionAuthor#MAX_AUTHOR_BYTES} is refused. Never throws.
     */
    public static Map<String, Object> loadActionsText(String text, String fmt) {
        if (Json.utf8(text).length > ActionAuthor.MAX_AUTHOR_BYTES) return fail("the file is larger than " + ActionAuthor.MAX_AUTHOR_BYTES + " bytes", 1, 1);
        List<Pos> positions = null;
        Object value;
        if (fmt.equals("json")) {
            try { value = Json.parseLenient(text); } catch (RuntimeException e) { return fail("not JSON: " + e.getMessage(), 1, 1); } // the reference reads with JSON.parse: last duplicate wins, any finite-or-not number
            // JSON is YAML: only the positions come from the YAML parse
            try { positions = positionsOf(parseDocument(text, false)); } catch (RuntimeException e) { positions = null; }
        } else {
            try {
                N root = parseDocument(text, true);
                value = toValue(root);
                positions = positionsOf(root);
            } catch (YamlLoadError e) { return fail("not YAML: " + e.getMessage(), e.line, e.column); }
        }
        Map<String, Object> res = ActionAuthor.loadActionsValue(value);
        if (positions != null) attachPositions(res, positions);
        return res;
    }

    public static Map<String, Object> loadActionsText(String text) { return loadActionsText(text, "yaml"); }
}
