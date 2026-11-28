package net.atlasauth.pca.goal;

import java.math.BigInteger;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Pca;

/**
 * The intent-fidelity ontology: the signed authoring vocabulary (types, units, relations, verbs, aliases, templates), its
 * well-formedness checker, the projection onto the Goal IR ontology, template instantiation and locale-aware amount parsing.
 * An ontology, a template and a slot value are parsed-JSON maps (numbers are Json.Num), like the reference objects.
 */
public final class GoalOntology {
    private GoalOntology() {}

    public static final List<String> EFFECT_CLASSES = List.of("read", "reversible", "external_send", "irreversible");

    private static final Pattern INVISIBLE = Pattern.compile("[\\u200B-\\u200F\\u2060\\uFEFF]");
    private static final Pattern NON_PRINTABLE = Pattern.compile("[^\\x20-\\x7e]");
    private static final Pattern ID_TAIL = Pattern.compile("[A-Za-z0-9_-]+");
    private static final long FOREVER = G.MAX_SAFE;

    private static Map<String, Object> mm(Object o) { return G.m(o); }

    private static String norm(String s) { return INVISIBLE.matcher(Normalizer.normalize(s, Normalizer.Form.NFKC).toLowerCase(java.util.Locale.ROOT)).replaceAll(""); }

    private static boolean hasOwn(Object m, String k) { return m instanceof Map && ((Map<?, ?>) m).containsKey(k); }

    private static List<Object> list(Object o) { return G.arr(o, ""); }

    private static String strOf(Object o) {
        if (!(o instanceof String)) throw new IrError("string expected");
        return (String) o;
    }

    // ---------------- digest and signing ----------------

    public static String ontologyDigest(Map<String, Object> o) { return Pca.hashCanonical(G.map("d", "atlas-pca/goal-intent-ontology/v1", "ontology", o)); }

    public static Map<String, Object> signOntology(Map<String, Object> o, byte[] seed) { return GoalSign.signPayload("ontology", o, seed); }

    public static boolean verifyOntology(Map<String, Object> s, List<?> pins) { return GoalSign.verifyPayload(s, "ontology", pins); }

    /** The declared canonical verb for {@code word} (the word itself when it is a verb id, else its alias); null when neither. Case and homoglyph variants are NOT guessed. */
    public static String resolveVerb(Map<String, Object> o, String word) {
        String w = AttestCommon.jsTrim(word);
        for (Object v : list(o.get("verbs"))) if (w.equals(G.get(v, "id"))) return w;
        Map<String, Object> al = mm(o.get("aliases"));
        if (al != null && al.containsKey(w)) { Object hit = al.get(w); return hit instanceof String ? (String) hit : null; }
        return null;
    }

    // ---------------- projection onto the IR ontology ----------------

    /** The currency a goal is written in: the first money quantity in its conditions or bound caps (null for a goal without money). */
    public static String goalCcy(Map<String, Object> g) {
        String[] found = {null};
        for (Object gr : list(g.get("grants"))) condCcy(mm(G.get(gr, "cond")), found);
        for (Object p : list(g.get("prohibits"))) condCcy(mm(G.get(p, "cond")), found);
        for (Object c : list(g.get("escalateOn"))) condCcy(mm(c), found);
        for (Object b : list(g.get("bounds"))) {
            if (found[0] == null) {
                Map<String, Object> u = mm(G.get(G.get(b, "cap"), "u"));
                if (u != null && "money".equals(u.get("k"))) found[0] = (String) u.get("ccy");
            }
        }
        return found[0];
    }

    private static void termCcy(Map<String, Object> x, String[] found) {
        if (x == null || !"lit".equals(x.get("k"))) return;
        Map<String, Object> v = mm(x.get("v"));
        List<Object> items = "set".equals(G.kind(v)) ? list(v.get("items")) : G.list(v);
        for (Object it : items) {
            if (found[0] == null && "q".equals(G.kind(it))) {
                Map<String, Object> u = mm(G.get(G.get(it, "q"), "u"));
                if (u != null && "money".equals(u.get("k"))) found[0] = (String) u.get("ccy");
            }
        }
    }

    private static void condCcy(Map<String, Object> x, String[] found) {
        String k = G.kind(x);
        if (k.equals("cmp")) { termCcy(mm(x.get("l")), found); termCcy(mm(x.get("r")), found); }
        else if (k.equals("and") || k.equals("or")) { condCcy(mm(x.get("a")), found); condCcy(mm(x.get("b")), found); }
        else if (k.equals("not")) condCcy(mm(x.get("c")), found);
    }

    private static Map<String, Object> paramTy(Map<String, Object> p, String ccy) {
        Object kind = p.get("kind");
        if ("id".equals(kind) || "enum".equals(kind) || "text".equals(kind)) return G.map("k", "s");
        if ("money".equals(kind)) {
            List<Object> ccys = G.l(p.get("ccys"));
            if (ccys == null) throw new IrError("money parameter lists no currency");
            Object c = ccy != null && ccys.contains(ccy) ? ccy : ccys.contains("USD") ? "USD" : ccys.isEmpty() ? null : ccys.get(0);
            Map<String, Object> u = G.map("k", "money");
            if (c != null) u.put("ccy", c); // an empty list has no first member: undefined, omitted
            return G.map("k", "q", "u", u);
        }
        return G.map("k", "q", "u", G.map("k", kind));
    }

    /** The Goal IR ontology (verbs with effect class and typed parameters, relation tables) of an intent ontology. {@code ccy} and {@code rels} may be null. */
    public static Map<String, Object> toIrOntology(Map<String, Object> o, String ccy, List<Object> rels) {
        List<Object> verbs = new ArrayList<>();
        for (Object vo : list(o.get("verbs"))) {
            Map<String, Object> v = mm(vo);
            Map<String, Object> params = mm(v.get("params"));
            List<String> keys = new ArrayList<>(params.keySet());
            keys.sort(String::compareTo);
            List<Object> ps = new ArrayList<>();
            for (String path : keys) ps.add(G.map("path", path, "ty", paramTy(mm(params.get(path)), ccy)));
            verbs.add(G.map("verb", v.get("id"), "cls", v.get("effect"), "params", ps));
        }
        return G.map("verbs", verbs, "rels", rels != null ? rels : new ArrayList<Object>());
    }

    /** The IR ontology a goal is typed and decided against: money parameters in the goal's own currency. */
    public static Map<String, Object> ontologyForGoal(Map<String, Object> o, Map<String, Object> g, List<Object> rels) {
        return toIrOntology(o, goalCcy(g), rels);
    }

    /** Relation anchors a goal mentions, declared with no members. */
    public static List<Object> goalAnchors(Map<String, Object> g) {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (Object gr : list(g.get("grants"))) anchorSel(mm(G.get(gr, "res")), out);
        for (Object p : list(g.get("prohibits"))) anchorSel(mm(G.get(p, "res")), out);
        List<String> keys = new ArrayList<>(out.keySet());
        keys.sort(String::compareTo);
        List<Object> r = new ArrayList<>();
        for (String k : keys) r.add(out.get(k));
        return r;
    }

    private static void anchorSel(Map<String, Object> s, Map<String, Map<String, Object>> out) {
        String k = G.kind(s);
        if (k.equals("related")) out.put(G.jsStr(s.get("rel")) + "\0" + G.jsStr(s.get("anchor")), G.map("rel", s.get("rel"), "anchor", s.get("anchor"), "members", new ArrayList<Object>()));
        else if (k.equals("all_of")) for (Object p : list(s.get("parts"))) anchorSel(mm(p), out);
    }

    // ---------------- template references ----------------

    private static List<String> d(String x) { return x.startsWith("$") ? List.of(x.substring(1)) : List.of(); }

    private static List<String> refsRes(Map<String, Object> s) {
        String k = G.kind(s);
        List<String> out = new ArrayList<>();
        if (k.equals("exact")) out.addAll(d(strOf(s.get("id"))));
        else if (k.equals("oneof")) for (Object i : list(s.get("ids"))) out.addAll(d(strOf(i)));
        else if (k.equals("related")) out.addAll(d(strOf(s.get("anchor"))));
        else if (k.equals("all_of")) for (Object p : list(s.get("parts"))) out.addAll(refsRes(mm(p)));
        return out;
    }

    private static List<String> refsTerm(Map<String, Object> x) { return "slot".equals(G.kind(x)) ? List.of(strOf(x.get("slot"))) : List.of(); }

    private static List<String> refsCond(Map<String, Object> c) {
        String k = G.kind(c);
        List<String> out = new ArrayList<>();
        if (k.equals("cmp")) { out.addAll(refsTerm(mm(c.get("l")))); out.addAll(refsTerm(mm(c.get("r")))); }
        else if (k.equals("and") || k.equals("or")) { out.addAll(refsCond(mm(c.get("a")))); out.addAll(refsCond(mm(c.get("b")))); }
        else if (k.equals("not")) out.addAll(refsCond(mm(c.get("c"))));
        return out;
    }

    private static List<String> refsGrant(Map<String, Object> g) { List<String> r = refsRes(mm(g.get("res"))); r.addAll(refsCond(mm(g.get("cond")))); return r; }

    private static List<String> refsBound(Map<String, Object> b) {
        Object cs = b.get("cap_slot");
        return G.truthy(cs) ? List.of(G.jsStr(cs)) : List.of();
    }

    private static List<String> slotRefs(Map<String, Object> t) {
        List<String> r = new ArrayList<>();
        for (Object g : list(t.get("grants"))) r.addAll(refsGrant(mm(g)));
        for (Object p : list(t.get("prohibits"))) r.addAll(refsGrant(mm(p)));
        for (Object b : list(t.get("bounds"))) r.addAll(refsBound(mm(b)));
        return r;
    }

    // ---------------- the well-formedness checker ----------------

    private static void bad(List<Object> I, String code, String where, String msg) { I.add(where == null ? G.map("code", code, "msg", msg) : G.map("code", code, "where", where, "msg", msg)); }

    private static boolean isInteger(Object v) {
        Double x = G.dbl(v);
        return x != null && !x.isNaN() && !x.isInfinite() && x == Math.floor(x);
    }

    private static Map<String, Object> findBy(Object listO, String key, Object val) {
        for (Object x : list(listO)) if (x instanceof Map && java.util.Objects.equals(((Map<?, ?>) x).get(key), val)) return mm(x);
        return null;
    }

    private static boolean strIncludes(Object listO, Object v) { List<Object> l = G.l(listO); return l != null && l.contains(v); }

    /** The reference's {@code x?.length} truthiness: a non-empty array or string. */
    private static boolean nonEmpty(Object o) { return o instanceof List ? !((List<?>) o).isEmpty() : o instanceof String && !((String) o).isEmpty(); }

    /** Property access on a JS value: an object itself, null throws (TypeError), any other value has no own members. */
    private static Map<String, Object> pm(Object o) {
        if (o == null) throw new NullPointerException("Cannot read properties of null");
        return o instanceof Map ? mm(o) : new LinkedHashMap<>();
    }

    /** {@code for (x of o)}: an array, or a string by code point; anything else is not iterable. */
    private static List<Object> iter(Object o) {
        if (o instanceof String) {
            List<Object> out = new ArrayList<>();
            ((String) o).codePoints().forEach(c -> out.add(new String(Character.toChars(c))));
            return out;
        }
        return G.arr(o, "");
    }

    /** {@code Object.entries(o)}: members of an object, index/character pairs of an array/string, none for other primitives; null throws. */
    private static List<Map.Entry<String, Object>> ents(Object o) {
        if (o == null) throw new NullPointerException("Cannot convert undefined or null to object");
        List<Map.Entry<String, Object>> out = new ArrayList<>();
        if (o instanceof Map) { for (Map.Entry<String, Object> e : mm(o).entrySet()) out.add(e); }
        else if (o instanceof List) { int i = 0; for (Object x : (List<?>) o) out.add(new java.util.AbstractMap.SimpleEntry<>(String.valueOf(i++), x)); }
        else if (o instanceof String) { int i = 0; for (Object x : iter(o)) out.add(new java.util.AbstractMap.SimpleEntry<>(String.valueOf(i++), x)); }
        return out;
    }

    /** A member rendered as in a template literal: a missing one prints undefined. */
    private static String js(Map<String, Object> m, String k) { return m.containsKey(k) ? G.jsStr(m.get(k)) : "undefined"; }

    /** A member used as a bare {@code where}: undefined is omitted from the issue. */
    private static String wo(Map<String, Object> m, String k) { return m.containsKey(k) ? G.jsStr(m.get(k)) : null; }

    /** Every defect of an intent ontology as {code, where, msg}; an empty list means well formed. */
    public static List<Object> checkOntology(Map<String, Object> o) {
        List<Object> I = new ArrayList<>();
        Set<Object> typeIds = new HashSet<>();
        Set<Object> prefixes = new HashSet<>();
        for (Object to : iter(o.get("types"))) {
            Map<String, Object> t = pm(to);
            if (typeIds.contains(t.get("id"))) bad(I, "dup_type", wo(t, "id"), "duplicate type id");
            typeIds.add(t.get("id"));
            Object pre = t.get("id_prefix");
            if (!G.truthy(pre) || prefixes.contains(pre)) bad(I, "dup_prefix", wo(t, "id"), "id prefix empty or reused");
            prefixes.add(pre);
        }
        List<Map.Entry<String, Object>> unitEnts = ents(o.get("units"));
        Map<String, Object> units = pm(o.get("units"));
        for (Map.Entry<String, Object> e : unitEnts) {
            String u = e.getKey();
            Map<String, Object> dd = pm(e.getValue());
            boolean money = "money".equals(dd.get("kind"));
            if (money) {
                Object ex = dd.get("exponent");
                Double x = G.dbl(ex);
                if (!(isInteger(ex) && x >= 0 && x <= 4)) bad(I, "unit_exponent", u, "money unit needs an integer exponent 0..4");
            }
            if (!money && dd.containsKey("exponent")) bad(I, "unit_exponent", u, "only money units carry an exponent");
        }
        Set<Object> relIds = new HashSet<>();
        for (Object ro : iter(o.get("relations"))) {
            Map<String, Object> r = pm(ro);
            if (relIds.contains(r.get("id"))) bad(I, "dup_relation", wo(r, "id"), "duplicate relation");
            relIds.add(r.get("id"));
            if (!typeIds.contains(r.get("from")) || !typeIds.contains(r.get("to"))) bad(I, "relation_type", wo(r, "id"), "relation endpoint type is not declared");
        }
        Set<Object> verbIds = new HashSet<>();
        Map<Object, Map<String, Object>> verbs = new LinkedHashMap<>();
        for (Object vo : iter(o.get("verbs"))) {
            Map<String, Object> v = pm(vo);
            String vid = js(v, "id");
            if (verbIds.contains(v.get("id"))) bad(I, "dup_verb", wo(v, "id"), "duplicate verb");
            verbIds.add(v.get("id"));
            verbs.put(v.get("id"), v);
            if (!EFFECT_CLASSES.contains(v.get("effect"))) bad(I, "no_effect_class", wo(v, "id"), "verb has no valid effect class");
            if (!typeIds.contains(v.get("resource_type"))) bad(I, "verb_resource_type", wo(v, "id"), "resource type is not declared");
            for (Map.Entry<String, Object> pe : ents(v.get("params"))) {
                String p = pe.getKey();
                Map<String, Object> pt = pm(pe.getValue());
                Object kind = pt.get("kind");
                if ("money".equals(kind)) {
                    if (!nonEmpty(pt.get("ccys"))) bad(I, "param_ccy", vid + "." + p, "money parameter lists no currency");
                    Object cs = pt.get("ccys");
                    if (cs != null) for (Object c : iter(cs)) {
                        Map<String, Object> ud = c instanceof String ? mm(units.get(c)) : null;
                        if (ud == null || !"money".equals(ud.get("kind"))) bad(I, "unit_unknown", vid + "." + p, "currency " + G.jsStr(c) + " is not a declared money unit");
                    }
                } else if ("enum".equals(kind)) { if (!nonEmpty(pt.get("values"))) bad(I, "param_enum", vid + "." + p, "enum parameter has no values"); }
                else if ("id".equals(kind)) { if (!G.truthy(pt.get("of")) || !typeIds.contains(pt.get("of"))) bad(I, "param_type", vid + "." + p, "id parameter type is not declared"); }
                else if (!"text".equals(kind)) {
                    boolean any = false;
                    for (Map.Entry<String, Object> ue : unitEnts) if (java.util.Objects.equals(G.get(ue.getValue(), "kind"), kind)) any = true;
                    if (!any) bad(I, "unit_unknown", vid + "." + p, "no declared unit of kind " + (pt.containsKey("kind") ? G.jsStr(kind) : "undefined"));
                }
            }
        }
        // Alias map: a function, keys normalized and collision-free, targets canonical, no chains or cycles.
        Map<String, Object> aliases = pm(o.get("aliases"));
        Map<String, String> seen = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : ents(o.get("aliases"))) {
            String k = e.getKey();
            Object target = e.getValue();
            if (!k.equals(norm(k)) || (NON_PRINTABLE.matcher(k).find() && !k.equals(Normalizer.normalize(k, Normalizer.Form.NFKC)))) bad(I, "alias_key", k, "alias key is not in normalized form");
            if (INVISIBLE.matcher(k).find()) bad(I, "alias_key", k, "alias key contains invisible characters");
            String n = norm(k);
            if (seen.containsKey(n) && !seen.get(n).equals(k)) bad(I, "alias_collision", k, "collides with " + seen.get(n) + " after normalization");
            seen.put(n, k);
            if (!verbIds.contains(target)) bad(I, "alias_target", k, "alias target is not a canonical verb");
            if (target instanceof String && aliases.containsKey(target)) bad(I, "alias_chain", k, "alias target is itself an alias (chain or cycle)");
            if (verbIds.contains(k) && !k.equals(target)) bad(I, "alias_shadow", k, "alias shadows a canonical verb");
        }
        // Templates.
        Set<Object> tids = new HashSet<>();
        for (Object to : iter(o.get("templates"))) {
            Map<String, Object> t = pm(to);
            String w = "template:" + js(t, "id");
            if (tids.contains(t.get("id"))) bad(I, "dup_template", w, "duplicate template id");
            tids.add(t.get("id"));
            List<Object> slots = list(t.get("slots"));
            Set<Object> slotNames = new LinkedHashSet<>();
            for (Object s : slots) slotNames.add(pm(s).get("name"));
            if (slotNames.size() != slots.size()) bad(I, "dup_slot", w, "duplicate slot");
            List<String> refs = slotRefs(t);
            for (String r : refs) if (!slotNames.contains(r)) bad(I, "slot_undeclared", w, "slot " + r + " is used but not declared");
            for (Object so : slots) {
                Map<String, Object> s = pm(so);
                String sw = w + "." + js(s, "name");
                Object sk = s.get("kind");
                if (("id".equals(sk) || "id_list".equals(sk)) && (!G.truthy(s.get("of")) || !typeIds.contains(s.get("of")))) bad(I, "slot_type", sw, "id slot type is not declared");
                if ("money".equals(sk)) {
                    Object cc = s.get("ccy");
                    Map<String, Object> ud = cc instanceof String ? mm(units.get(cc)) : mm(units.get(""));
                    if (cc == null) ud = mm(units.get(""));
                    if (ud == null || !"money".equals(ud.get("kind"))) bad(I, "slot_ccy", sw, "money slot currency is not a declared unit");
                }
                if (("enum".equals(sk) || "enum_list".equals(sk)) && !nonEmpty(s.get("values"))) bad(I, "slot_enum", sw, "enum slot has no values");
                if (!G.truthy(s.get("mandatory")) && !s.containsKey("default")) bad(I, "slot_default", sw, "optional slot needs a default (an unfilled slot must be a hole or a default)");
                if (!refs.contains(js(s, "name"))) bad(I, "slot_unused", sw, "declared slot is never used");
            }
            List<Object> tgrants = list(t.get("grants"));
            if (tgrants.isEmpty()) bad(I, "empty_allow", w, "template has no grant (empty Allow set)");
            Set<Object> gids = new LinkedHashSet<>();
            for (Object g : tgrants) gids.add(pm(g).get("gid"));
            if (gids.size() != tgrants.size()) bad(I, "dup_gid", w, "duplicate grant id");
            for (Object go : tgrants) {
                Map<String, Object> g = pm(go);
                Map<String, Object> v = verbs.get(g.get("verb"));
                String gw = w + "." + js(g, "gid");
                if (v == null) { bad(I, "grant_verb", gw, "grant verb is not in the ontology"); continue; }
                checkResource(o, mm(g.get("res")), v, gw, I);
                checkCond(mm(g.get("cond")), v, t, gw, I);
                Map<String, Object> gres = mm(g.get("res"));
                if ("any".equals(G.kind(gres)) && !("read".equals(v.get("effect")) && !list(t.get("bounds")).isEmpty())) bad(I, "unbounded", gw, "wildcard resource in a template");
                if (!"read".equals(v.get("effect")) && "related".equals(G.kind(gres)) && list(t.get("bounds")).isEmpty()) bad(I, "unbounded", gw, "non-read grant on a related set needs an aggregate bound");
            }
            for (Object po : iter(t.get("prohibits"))) {
                Map<String, Object> p = pm(po);
                Map<String, Object> tg = pm(p.get("target"));
                String pw = w + "." + js(p, "pid");
                if ("verb".equals(G.kind(tg)) && !verbs.containsKey(tg.get("verb"))) bad(I, "prohibit_verb", pw, "prohibit verb is not in the ontology");
                if ("effect".equals(G.kind(tg)) && !EFFECT_CLASSES.contains(tg.get("cls"))) bad(I, "prohibit_effect", pw, "unknown effect class");
            }
            for (Object bo : list(t.get("bounds"))) {
                Map<String, Object> b = pm(bo);
                String bw = w + "." + js(b, "bid");
                Object over = b.get("over");
                if (!"all".equals(over)) {
                    boolean unknown = false;
                    for (Object x : iter(over)) if (!gids.contains(x)) unknown = true;
                    if (unknown) bad(I, "bound_over", bw, "bound selects an unknown grant");
                }
                Object cslot = b.get("cap_slot");
                if (G.truthy(cslot) && !slotNames.contains(cslot)) bad(I, "slot_undeclared", w, "cap slot " + G.jsStr(cslot) + " is not declared");
                if (G.truthy(cslot)) {
                    Map<String, Object> cs = findBy(slots, "name", cslot);
                    Object ck = cs == null ? null : cs.get("kind");
                    Object agg = b.get("agg");
                    if (cs != null && !("money".equals(ck) || "count".equals(ck))) bad(I, "bound_cap", bw, "cap slot must be money or count");
                    if (cs != null && "count".equals(agg) && !"count".equals(ck)) bad(I, "bound_cap", bw, "count bound needs a count slot");
                    if (cs != null && "sum".equals(agg) && !"money".equals(ck)) bad(I, "bound_cap", bw, "sum bound over money needs a money slot");
                }
                if ("sum".equals(b.get("agg")) && !G.truthy(b.get("param"))) bad(I, "bound_value", bw, "sum bound has no value parameter");
            }
            // non-empty and bounded after instantiation with the declared example
            Map<String, Object> g = instantiateTemplate(o, strOf(t.get("id")), mm(t.get("example")), "p", "", null);
            List<Object> holes = list(g.get("holes"));
            if (!holes.isEmpty()) {
                List<String> hs = new ArrayList<>();
                for (Object h : holes) hs.add(G.jsStr(G.get(h, "hid")));
                bad(I, "example_holes", w, "example leaves holes: " + String.join(",", hs));
            } else if (list(g.get("grants")).size() != tgrants.size()) bad(I, "empty_allow", w, "example instantiation dropped a grant");
            else if (!hasAllowWitness(o, g)) bad(I, "empty_allow", w, "instantiated template has an empty Allow set");
        }
        return I;
    }

    private static String prefixOf(Map<String, Object> o, Object typeId) {
        Map<String, Object> t = findBy(o.get("types"), "id", typeId);
        return t == null ? null : (String) t.get("id_prefix");
    }

    private static boolean idOk(String id, String pre) { return id.startsWith("$") || (pre != null && id.startsWith(pre)); }

    private static void checkResource(Map<String, Object> o, Map<String, Object> s, Map<String, Object> v, String w, List<Object> I) {
        String prefix = prefixOf(o, v.get("resource_type"));
        String k = G.kind(s);
        if (k.equals("exact") && !idOk(strOf(s.get("id")), prefix)) bad(I, "resource_type", w, "exact resource id has the wrong type prefix");
        else if (k.equals("oneof")) {
            List<Object> ids = list(s.get("ids"));
            if (ids.isEmpty()) bad(I, "resource_empty", w, "one_of is empty");
            for (Object i : ids) if (!idOk(strOf(i), prefix)) bad(I, "resource_type", w, "one_of member has the wrong type prefix");
        } else if (k.equals("related")) {
            Map<String, Object> r = findBy(o.get("relations"), "id", s.get("rel"));
            if (r == null) bad(I, "relation_unknown", w, "relation " + G.jsStr(s.get("rel")) + " is not declared");
            else {
                if (!java.util.Objects.equals(r.get("to"), v.get("resource_type"))) bad(I, "relation_type", w, "relation target type differs from the verb resource type");
                String anchorPre = prefixOf(o, r.get("from"));
                if (!idOk(strOf(s.get("anchor")), anchorPre)) bad(I, "resource_type", w, "relation anchor has the wrong type prefix");
            }
        } else if (k.equals("all_of")) {
            List<Object> parts = list(s.get("parts"));
            if (parts.size() < 2) bad(I, "all_of_arity", w, "all_of needs at least two parts");
            for (Object x : parts) checkResource(o, mm(x), v, w, I);
        }
    }

    private static void checkCond(Map<String, Object> c, Map<String, Object> v, Map<String, Object> t, String w, List<Object> I) {
        String k = G.kind(c);
        if (k.equals("and") || k.equals("or")) { checkCond(mm(c.get("a")), v, t, w, I); checkCond(mm(c.get("b")), v, t, w, I); return; }
        if (k.equals("not")) { checkCond(mm(c.get("c")), v, t, w, I); return; }
        if (!k.equals("cmp")) return;
        Map<String, Object> l = mm(c.get("l"));
        Map<String, Object> p = "param".equals(G.kind(l)) ? mm(mm(v.get("params")).get(l.get("path"))) : null;
        if (!"param".equals(G.kind(l)) || p == null) { bad(I, "cond_param", w, "left side of a comparison must be a declared parameter of the verb"); return; }
        Object op = c.get("op");
        boolean ordered = "lt".equals(op) || "lte".equals(op) || "gt".equals(op) || "gte".equals(op);
        Object pk = p.get("kind");
        if (ordered && ("text".equals(pk) || "enum".equals(pk) || "id".equals(pk))) bad(I, "cond_order", w, "ordering on a text/enum/id parameter");
        Map<String, Object> x = mm(c.get("r"));
        String xk = G.kind(x);
        boolean inOp = "in".equals(op) || "nin".equals(op);
        if (xk.equals("slot")) {
            Map<String, Object> s = findBy(t.get("slots"), "name", x.get("slot"));
            if (s == null) return;
            Object sk = s.get("kind");
            boolean okKind = "money".equals(pk) ? "money".equals(sk)
                : java.util.Objects.equals(pk, sk) || ("enum".equals(pk) && ("enum".equals(sk) || "enum_list".equals(sk))) || ("id".equals(pk) && ("id".equals(sk) || "id_list".equals(sk))) || ("text".equals(pk) && "text_list".equals(sk));
            if (!okKind) bad(I, "cond_type", w, "slot " + G.jsStr(s.get("name")) + " (" + G.jsStr(sk) + ") does not type-check against parameter kind " + G.jsStr(pk));
            if ("money".equals(pk) && "money".equals(sk) && !strIncludes(p.get("ccys"), s.get("ccy") == null ? "" : s.get("ccy"))) bad(I, "cond_unit", w, "slot currency is not accepted by the parameter");
            boolean isList = "id_list".equals(sk) || "enum_list".equals(sk) || "text_list".equals(sk);
            if (isList != inOp) bad(I, "cond_type", w, "list slots pair with in/nin and scalar slots with the other operators");
        } else if (xk.equals("lit")) {
            Map<String, Object> lv = mm(x.get("v"));
            if ("set".equals(G.kind(lv))) {
                List<Object> items = list(lv.get("items"));
                if (items.isEmpty()) bad(I, "cond_type", w, "empty literal list");
                for (Object i : items) litCheck(mm(i), p, w, I);
                if (!inOp) bad(I, "cond_type", w, "a literal set pairs with in/nin");
            } else {
                litCheck(lv, p, w, I);
                if (inOp) bad(I, "cond_type", w, "in/nin needs a list");
            }
        } else bad(I, "cond_term", w, "unsupported right-hand term");
    }

    private static void litCheck(Map<String, Object> l, Map<String, Object> p, String w, List<Object> I) {
        String k = G.kind(l);
        Object pk = p.get("kind");
        if (k.equals("q")) {
            Map<String, Object> u = mm(G.get(l.get("q"), "u"));
            if (!java.util.Objects.equals(u.get("k"), pk)) bad(I, "cond_type", w, "literal kind differs from the parameter kind");
            if ("money".equals(u.get("k")) && !strIncludes(p.get("ccys"), u.get("ccy"))) bad(I, "cond_unit", w, "literal currency is not accepted by the parameter");
        } else if (k.equals("s")) {
            if (!"enum".equals(pk) && !"id".equals(pk) && !"text".equals(pk)) bad(I, "cond_type", w, "literal kind differs from the parameter kind");
            if ("enum".equals(pk) && !strIncludes(p.get("values"), l.get("s"))) bad(I, "cond_enum", w, "enum literal is not a member");
        } else bad(I, "cond_type", w, "nested literal set");
    }

    private static boolean hasAllowWitness(Map<String, Object> o, Map<String, Object> g) {
        Map<String, Object> ont = ontologyForGoal(o, g, null);
        for (Object gr : list(g.get("grants"))) if (GoalExamples.allowWitness(g, mm(gr), ont) == null) return false;
        return true;
    }

    // ---------------- template instantiation ----------------

    private static Map<String, Object> quantityOf(Map<String, Object> s, Object v) {
        if (v instanceof String || v instanceof List) return null;
        if (!(v instanceof Map)) throw new IrError("slot value is not an object");
        Map<String, Object> m = mm(v);
        Object kind = s.get("kind");
        if (m.containsKey("minor") && "money".equals(kind) && java.util.Objects.equals(m.get("ccy"), s.get("ccy"))) {
            Long n = G.safeInt(m.get("minor"));
            if (n != null && n >= 0) return G.map("u", G.map("k", "money", "ccy", m.get("ccy")), "n", G.num(n));
        }
        if (m.containsKey("n") && "count".equals(kind)) {
            Long n = G.safeInt(m.get("n"));
            if (n != null && n >= 0) return G.map("u", G.map("k", "count"), "n", G.num(n));
        }
        if (m.containsKey("ms") && "duration".equals(kind)) {
            Long n = G.safeInt(m.get("ms"));
            if (n != null && n >= 0) return G.map("u", G.map("k", "duration"), "n", G.num(n));
        }
        if (m.containsKey("epoch_ms") && "instant".equals(kind)) {
            Long n = G.safeInt(m.get("epoch_ms"));
            if (n != null) return G.map("u", G.map("k", "instant"), "n", G.num(n));
        }
        return null;
    }

    private static Map<String, Object> sv(Object s) { return G.map("k", "s", "s", s); }

    private static boolean idLike(String v) { return ID_TAIL.matcher(v).matches(); }

    private static boolean noInvisible(String x) { return x.equals(Normalizer.normalize(x, Normalizer.Form.NFKC)) && !INVISIBLE.matcher(x).find(); }

    /** Typed value(s) of a slot (a List of values), or a reason String when it is missing or invalid (the slot then becomes a Hole). */
    public static Object slotLits(Map<String, Object> o, Map<String, Object> s, Object v) {
        if (v == null) return "missing";
        String kind = G.jsStr(s.get("kind"));
        switch (kind) {
            case "money": case "count": case "duration": case "instant": {
                Map<String, Object> q = quantityOf(s, v);
                if (q == null) return "ill-typed";
                Double max = s.get("max") == null ? null : G.dbl(s.get("max"));
                if (max != null) {
                    double qn = kind.equals("instant") ? 0 : G.toNum(q.get("n"));
                    if (qn > max) return "above the template maximum";
                }
                return G.list(G.map("k", "q", "q", q));
            }
            case "id": {
                String pre = prefixOf(o, s.get("of"));
                return v instanceof String && pre != null && !pre.isEmpty() && ((String) v).startsWith(pre) && ((String) v).length() > pre.length() && idLike((String) v) ? G.list(sv(v)) : "ill-typed";
            }
            case "id_list": {
                String pre = prefixOf(o, s.get("of"));
                if (!(v instanceof List) || ((List<?>) v).isEmpty()) return "ill-typed";
                List<Object> out = new ArrayList<>();
                for (Object x : (List<?>) v) {
                    String xs = strOf(x);
                    if (!(pre != null && !pre.isEmpty() && xs.startsWith(pre) && idLike(xs))) return "ill-typed";
                    out.add(sv(x));
                }
                return out;
            }
            case "enum": return v instanceof String && strIncludes(s.get("values"), v) ? G.list(sv(v)) : "ill-typed";
            case "enum_list": {
                if (!(v instanceof List) || ((List<?>) v).isEmpty()) return "ill-typed";
                List<Object> out = new ArrayList<>();
                for (Object x : (List<?>) v) { if (!strIncludes(s.get("values"), x)) return "ill-typed"; out.add(sv(x)); }
                return out;
            }
            case "text_list": {
                if (!(v instanceof List) || ((List<?>) v).isEmpty()) return "ill-typed";
                List<Object> out = new ArrayList<>();
                for (Object x : (List<?>) v) {
                    if (!(x instanceof String) || ((String) x).isEmpty() || !noInvisible((String) x)) return "ill-typed";
                    out.add(sv(x));
                }
                return out;
            }
            default: return null;
        }
    }

    private static boolean isListSlot(Map<String, Object> t, String name) {
        Map<String, Object> s = findBy(t.get("slots"), "name", name);
        return s != null && s.get("kind") instanceof String && ((String) s.get("kind")).endsWith("_list");
    }

    /**
     * Template -&gt; Goal (canonical order). Mandatory slots that are missing or ill-typed become Holes; every clause depending on a hole
     * is dropped (the most restrictive completion). {@code sources} may be null.
     */
    public static Map<String, Object> instantiateTemplate(Map<String, Object> o, String templateId, Map<String, Object> values, String principal, String nl, List<String> sources) {
        Map<String, Object> t = findBy(o.get("templates"), "id", templateId);
        if (t == null) throw new IrError("unknown template " + templateId);
        Map<String, List<Object>> bound = new LinkedHashMap<>();
        List<Object> holes = new ArrayList<>();
        for (Object so : list(t.get("slots"))) {
            Map<String, Object> s = mm(so);
            String name = G.jsStr(s.get("name"));
            Object val = values == null ? null : values.get(name);
            if (val == null) val = s.get("default");
            Object r = slotLits(o, s, val);
            if (r instanceof String) {
                holes.add(G.map("hid", name, "q", "What is the " + name.replace("_", " ") + " (" + G.jsStr(s.get("kind")) + (G.truthy(s.get("ccy")) ? " " + G.jsStr(s.get("ccy")) : "") + ")? (" + r + ")",
                    "domain", new ArrayList<Object>(), "affects", new ArrayList<Object>(), "global", false));
            } else {
                @SuppressWarnings("unchecked") List<Object> rl = (List<Object>) r;
                bound.put(name, rl);
            }
        }
        Map<Object, Map<String, Object>> verbOf = new LinkedHashMap<>();
        for (Object vo : list(o.get("verbs"))) verbOf.put(G.get(vo, "id"), mm(vo));
        Inst in = new Inst(o, t, bound, verbOf);
        Set<String> dropped = new HashSet<>();
        List<Object> grants = new ArrayList<>();
        List<Object> tbounds = list(t.get("bounds"));
        List<Object> keepBound = new ArrayList<>();
        for (Object b : tbounds) if (in.deps(refsBound(mm(b)))) keepBound.add(b);
        for (Object bo : tbounds) {
            if (keepBound.contains(bo)) continue;
            Map<String, Object> b = mm(bo);
            for (Object go : list(t.get("grants"))) {
                Object gid = G.get(go, "gid");
                if ("all".equals(b.get("over")) || list(b.get("over")).contains(gid)) dropped.add(G.jsStr(gid));
            }
        }
        for (Object go : list(t.get("grants"))) {
            Map<String, Object> g = mm(go);
            String gid = G.jsStr(g.get("gid"));
            if (dropped.contains(gid) || !in.deps(refsGrant(g))) dropped.add(gid);
            else grants.add(G.map("gid", g.get("gid"), "verb", g.get("verb"), "res", in.subRes(mm(g.get("res"))), "cond", in.subCond(mm(g.get("cond")), (String) g.get("verb"))));
        }
        List<Object> prohibits = new ArrayList<>();
        for (Object po : list(t.get("prohibits"))) {
            Map<String, Object> p = mm(po);
            Map<String, Object> tg = mm(p.get("target"));
            String verb;
            if ("verb".equals(G.kind(tg))) verb = (String) tg.get("verb");
            else {
                verb = null;
                for (Object vo : list(o.get("verbs"))) if (java.util.Objects.equals(G.get(vo, "effect"), tg.get("cls"))) { verb = (String) G.get(vo, "id"); break; }
            }
            if (in.deps(refsGrant(p))) prohibits.add(G.map("pid", p.get("pid"), "target", tg, "res", in.subRes(mm(p.get("res"))), "cond", in.subCond(mm(p.get("cond")), verb)));
            else prohibits.add(G.map("pid", p.get("pid"), "target", tg, "res", G.map("k", "any", "reason", "hole"), "cond", G.map("k", "true")));
        }
        Set<String> kept = new HashSet<>();
        for (Object g : grants) kept.add(G.jsStr(G.get(g, "gid")));
        List<Object> bounds = new ArrayList<>();
        for (Object bo : keepBound) {
            Map<String, Object> b = mm(bo);
            List<Object> gids = new ArrayList<>();
            if ("all".equals(b.get("over"))) for (Object g : grants) gids.add(G.get(g, "gid"));
            else for (Object x : list(b.get("over"))) if (kept.contains(G.jsStr(x))) gids.add(x);
            if (gids.isEmpty()) continue;
            Object capSlot = b.get("cap_slot");
            Map<String, Object> capLit = G.truthy(capSlot) ? in.single(G.jsStr(capSlot)) : null;
            Map<String, Object> cap = capLit != null && "q".equals(G.kind(capLit)) ? mm(capLit.get("q")) : mm(b.get("cap"));
            String verb = null;
            for (Object g : grants) if (java.util.Objects.equals(G.get(g, "gid"), gids.get(0))) { verb = (String) G.get(g, "verb"); break; }
            if (verb == null) throw new IrError("bound without a surviving grant");
            Map<String, Object> value;
            if ("sum".equals(b.get("agg"))) {
                if (!(b.get("param") instanceof String)) throw new IrError("parameter undefined is not declared by any verb");
                Map<String, Object> cu = mm(cap.get("u"));
                value = G.map("k", "param", "path", b.get("param"), "ty", in.tyOf(verb, (String) b.get("param"), "money".equals(cu.get("k")) ? (String) cu.get("ccy") : null));
            } else value = G.map("k", "lit", "v", G.map("k", "q", "q", G.map("u", G.map("k", "count"), "n", G.num(1))));
            bounds.add(G.map("bid", b.get("bid"), "sel", G.map("k", "gids", "gids", gids), "agg", b.get("agg"), "value", value, "key", "",
                "window", G.map("k", "lifetime"), "scope", G.map("k", "session"), "cap", cap, "onExceed", b.get("onExceed")));
        }
        List<Object> srcs = new ArrayList<>();
        if (sources != null) srcs.addAll(sources);
        return GoalNormalize.canonicalizeGoal(G.map(
            "v", G.num(1), "principal", principal, "ontDigest", ontologyDigest(o), "nlDigest", GoalDigests.nlDigest(nl), "sources", srcs,
            "grants", grants, "prohibits", prohibits, "bounds", bounds,
            "validity", G.map("notBefore", G.num(0), "notAfter", G.num(FOREVER), "maxIdle", G.num(0)),
            "deleg", G.map("maxDepth", G.num(0), "narrowOnly", true, "mayTouch", new ArrayList<Object>()),
            "escalateOn", new ArrayList<Object>(), "wildcardAck", new ArrayList<Object>(), "holes", holes));
    }

    /** The substitution state of one instantiation. */
    private static final class Inst {
        final Map<String, Object> o, t;
        final Map<String, List<Object>> bound;
        final Map<Object, Map<String, Object>> verbOf;

        Inst(Map<String, Object> o, Map<String, Object> t, Map<String, List<Object>> bound, Map<Object, Map<String, Object>> verbOf) { this.o = o; this.t = t; this.bound = bound; this.verbOf = verbOf; }

        boolean deps(List<String> refs) { for (String r : refs) if (!bound.containsKey(r)) return false; return true; }

        Map<String, Object> single(String name) { return mm(bound.get(name).get(0)); }

        String sub(String id) { return id.startsWith("$") ? (String) single(id.substring(1)).get("s") : id; }

        Map<String, Object> subPart(Map<String, Object> r) {
            String k = G.kind(r);
            if (k.equals("exact")) return G.map("k", "exact", "id", sub(strOf(r.get("id"))));
            if (k.equals("oneof")) { List<Object> ids = new ArrayList<>(); for (Object i : list(r.get("ids"))) ids.add(sub(strOf(i))); return G.map("k", "oneof", "ids", ids); }
            Map<String, Object> c = new LinkedHashMap<>(r);
            c.put("anchor", sub(strOf(r.get("anchor"))));
            return c;
        }

        Map<String, Object> subRes(Map<String, Object> r) {
            String k = G.kind(r);
            if (k.equals("any")) return r;
            if (k.equals("all_of")) { List<Object> ps = new ArrayList<>(); for (Object p : list(r.get("parts"))) ps.add(subPart(mm(p))); return G.map("k", "all_of", "parts", ps); }
            return subPart(r);
        }

        Map<String, Object> tyOf(String verb, String path, String ccy) {
            Map<String, Object> p = null;
            Map<String, Object> v = verb != null ? verbOf.get(verb) : null;
            if (v != null) p = mm(mm(v.get("params")).get(path));
            if (p == null) for (Object vo : list(o.get("verbs"))) { Map<String, Object> x = mm(mm(G.get(vo, "params")).get(path)); if (x != null) { p = x; break; } }
            if (p == null) throw new IrError("parameter " + path + " is not declared by any verb");
            return paramTy(p, ccy);
        }

        Map<String, Object> lit(Map<String, Object> x) {
            String k = G.kind(x);
            if (k.equals("slot")) {
                String slot = strOf(x.get("slot"));
                List<Object> l = bound.get(slot);
                return G.map("k", "lit", "v", isListSlot(t, slot) ? G.map("k", "set", "items", l) : l.get(0));
            }
            return k.equals("lit") ? G.map("k", "lit", "v", x.get("v")) : null;
        }

        String ccyOf(Map<String, Object> x) {
            if (x != null && "lit".equals(x.get("k"))) {
                Map<String, Object> v = mm(x.get("v"));
                if ("q".equals(G.kind(v))) { Map<String, Object> u = mm(G.get(v.get("q"), "u")); if (u != null && "money".equals(u.get("k"))) return (String) u.get("ccy"); }
            }
            return null;
        }

        Map<String, Object> term(Map<String, Object> x, Map<String, Object> v, String verb, String hint) {
            if (v != null) return v;
            String path = strOf(x.get("path"));
            return G.map("k", "param", "path", path, "ty", tyOf(verb, path, hint));
        }

        Map<String, Object> subCond(Map<String, Object> c, String verb) {
            String k = G.kind(c);
            if (k.equals("true")) return c;
            if (k.equals("and")) return G.map("k", "and", "a", subCond(mm(c.get("a")), verb), "b", subCond(mm(c.get("b")), verb));
            if (k.equals("or")) return G.map("k", "or", "a", subCond(mm(c.get("a")), verb), "b", subCond(mm(c.get("b")), verb));
            if (k.equals("not")) return G.map("k", "not", "c", subCond(mm(c.get("c")), verb));
            Map<String, Object> l = mm(c.get("l")), r = mm(c.get("r"));
            Map<String, Object> lv = lit(l), rv = lit(r);
            String hint = ccyOf(lv);
            if (hint == null) hint = ccyOf(rv);
            Map<String, Object> tl = term(l, lv, verb, hint);
            Map<String, Object> tr = term(r, rv, verb, hint);
            return G.map("k", "cmp", "op", c.get("op"), "l", tl, "r", tr);
        }
    }

    // ---------------- locale-aware human number parsing ----------------

    private static Map<String, Object> amountFail(String reason) { return G.map("ok", false, "reason", reason); }

    private static final Pattern NOT_AMOUNT_CHAR = Pattern.compile("[^0-9.,]");
    private static final Pattern AMOUNT = Pattern.compile("[0-9][0-9.,]*");
    private static final Pattern DOUBLE_SEP = Pattern.compile("[.,]{2}");
    private static final Pattern DIGITS = Pattern.compile("[0-9]+");

    private static int count(String t, char sep) { int n = 0; for (int i = 0; i < t.length(); i++) if (t.charAt(i) == sep) n++; return n; }

    /**
     * "1,000.50", "1.000,50", "$20", "20 dollars": {ok: true, minor} or {ok: false, reason}. Ambiguous literals ("1,000" with no locale
     * hint, "1.000") are NOT guessed. {@code locale} is "en" (',' is thousands), "de" ('.' is thousands) or null.
     */
    public static Map<String, Object> parseHumanAmount(String text, int exponent, String locale) {
        String t = NOT_AMOUNT_CHAR.matcher(AttestCommon.jsTrim(Normalizer.normalize(text, Normalizer.Form.NFKC))).replaceAll("");
        if (!AMOUNT.matcher(t).matches() || DOUBLE_SEP.matcher(t).find()) return amountFail("not a number");
        int lastDot = t.lastIndexOf('.'), lastComma = t.lastIndexOf(',');
        Character dec = null, thou = null;
        if (lastDot >= 0 && lastComma >= 0) { dec = lastDot > lastComma ? '.' : ','; thou = dec == '.' ? ',' : '.'; }
        else if (lastDot >= 0 || lastComma >= 0) {
            char sep = lastDot >= 0 ? '.' : ',';
            String[] parts = t.split(Pattern.quote(String.valueOf(sep)), -1);
            boolean groupLike = parts.length > 2 || parts[parts.length - 1].length() == 3;
            if (!groupLike) dec = sep;
            else if (parts.length > 2) thou = sep;
            else if (locale != null && !locale.isEmpty()) { if (locale.equals("en") == (sep == ',')) thou = sep; else dec = sep; }
            else return amountFail("ambiguous separator");
        }
        String intPart = t, frac = "";
        if (dec != null) { int i = t.lastIndexOf(dec); intPart = t.substring(0, i); frac = t.substring(i + 1); }
        if (thou != null) {
            String[] groups = intPart.split(Pattern.quote(String.valueOf(thou)), -1);
            boolean badGroup = false;
            for (int i = 1; i < groups.length; i++) if (groups[i].length() != 3) badGroup = true;
            if (badGroup || groups[0].length() == 0 || groups[0].length() > 3) return amountFail("malformed grouping");
            intPart = String.join("", groups);
        }
        if (frac.length() > exponent) return amountFail("more decimals than the currency allows");
        StringBuilder sb = new StringBuilder(intPart).append(frac);
        for (int i = frac.length(); i < exponent; i++) sb.append('0');
        String digits = sb.toString();
        if (!DIGITS.matcher(digits).matches()) return amountFail("out of range");
        BigInteger v = new BigInteger(digits);
        if (v.compareTo(BigInteger.valueOf(G.MAX_SAFE)) > 0) return amountFail("out of range");
        return G.map("ok", true, "minor", G.num(v.longValue()));
    }

    private static final Pattern LEAD_SYMBOL = Pattern.compile("^[$€£]" + GoalInterpret.JSWS + "*");

    /**
     * The strict front-end contract over {@link #parseHumanAmount}: {minor} | {hole: "AMBIGUOUS_NUMBER"} | {error: "BAD_NUMBER"}.
     * Only digits, '.' and ',' after one optional leading currency symbol; a decimal separator that contradicts the locale is refused.
     */
    public static Map<String, Object> parseMoney(String text, int exponent, String locale) {
        String t = LEAD_SYMBOL.matcher(AttestCommon.jsTrim(text)).replaceFirst("");
        if (!AMOUNT.matcher(t).matches()) return G.map("error", "BAD_NUMBER");
        boolean both = t.indexOf('.') >= 0 && t.indexOf(',') >= 0;
        if (locale != null && both && t.charAt(Math.max(t.lastIndexOf('.'), t.lastIndexOf(','))) != (locale.equals("en") ? '.' : ',')) return G.map("error", "BAD_NUMBER");
        if (locale == null && !both && count(t, '.') + count(t, ',') > 1) return G.map("hole", "AMBIGUOUS_NUMBER");
        Map<String, Object> r = parseHumanAmount(t, exponent, locale);
        if (Boolean.TRUE.equals(r.get("ok"))) return G.map("minor", r.get("minor"));
        return "ambiguous separator".equals(r.get("reason")) ? G.map("hole", "AMBIGUOUS_NUMBER") : G.map("error", "BAD_NUMBER");
    }
}
