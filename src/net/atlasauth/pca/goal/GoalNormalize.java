package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/** Canonical form of a Goal: id-sorted clauses (code-unit order); duplicated ids are kept (the typechecker refuses them). */
public final class GoalNormalize {
    private GoalNormalize() {}

    /** Stable JSON (sorted keys): an in-memory key for maps and sets, not a signed encoding. */
    public static String stable(Object v) { return G.stable(v); }

    private static List<Object> byId(Object xs, String field) {
        List<Object> out = new ArrayList<>(G.arr(xs, field));
        // stable sort, like Array.prototype.sort
        out.sort(Comparator.comparing((Object x) -> (String) G.get(x, field), String::compareTo));
        return out;
    }

    private static List<Object> sortedSet(Object xs) {
        TreeSet<String> s = new TreeSet<>();
        for (Object o : G.arr(xs, "")) s.add((String) o);
        return new ArrayList<Object>(s);
    }

    public static Map<String, Object> canonicalizeGoal(Map<String, Object> g) {
        Map<String, Object> out = new LinkedHashMap<>(g);
        out.put("grants", byId(g.get("grants"), "gid"));
        out.put("prohibits", byId(g.get("prohibits"), "pid"));
        out.put("bounds", byId(g.get("bounds"), "bid"));
        out.put("holes", byId(g.get("holes"), "hid"));
        out.put("wildcardAck", sortedSet(g.get("wildcardAck")));
        Map<String, Object> d = new LinkedHashMap<>(G.m(g.get("deleg")));
        d.put("mayTouch", sortedSet(d.get("mayTouch")));
        out.put("deleg", d);
        return out;
    }
}
