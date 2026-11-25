package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;
import net.atlasauth.pca.Actions;

/**
 * Keep a platform's action definitions in step with the sources they were imported from. Pure: the caller fetches the source and stores the lock. The lock
 * records, per source, the digest of each operation AS IMPORTED (before any review). On the next sync an operation is {@code added} (lands as imported,
 * unreviewed, so strict), {@code changed} (the NEW imported form replaces the reviewed def and is unreviewed until a reviewer confirms it again; the semantic
 * diff is reported), {@code unchanged} (the current, possibly reviewed, def is kept) or {@code removed} (deprecated). A def the lock does not attribute to
 * this source is never touched.
 */
public final class ActionSync {
    private ActionSync() {}

    /** Strip the review to the imported state: a changed operation is never carried over as confirmed. */
    private static Map<String, Object> asImported(Map<String, Object> d) {
        Object rv = d.get("review");
        if (!(rv instanceof Map)) throw new IllegalArgumentException("the def has no review");
        if (!"confirmed".equals(J.m(rv).get("state"))) return d;
        Map<String, Object> c = new LinkedHashMap<>(d);
        c.put("review", J.obj("state", "unreviewed"));
        return c;
    }

    /**
     * Merge a fresh import of one source into the current defs: {@code {defs, entries, deprecated, lock, needsReview}}. {@code lock} may be null;
     * {@code now}: seconds since the epoch of this sync. {@code reg} null is the core registry; {@code attestationVerified} may be null.
     */
    public static Map<String, Object> syncSource(List<?> current, List<?> imported, String specDigest, Map<String, Object> lock, Object now, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified) {
        Actions.Registry r = reg == null ? Actions.CORE_REGISTRY : reg;
        Map<String, Map<String, Object>> cur = new LinkedHashMap<>();
        for (Object d : current) cur.put((String) J.get(d, "verb"), J.m(d));
        TreeMap<String, Map<String, Object>> imp = new TreeMap<>();
        for (Object d : imported) imp.put((String) J.get(d, "verb"), asImported(J.m(d)));
        Map<String, Object> lockOps = lock != null && lock.get("ops") instanceof Map ? J.m(lock.get("ops")) : new LinkedHashMap<>();
        Map<String, Object> ops = new LinkedHashMap<>();
        List<Object> entries = new ArrayList<>(), defs = new ArrayList<>();
        for (Map.Entry<String, Map<String, Object>> e : imp.entrySet()) {
            String verb = e.getKey();
            Map<String, Object> d = e.getValue();
            String dg = Actions.defDigest(d);
            ops.put(verb, dg);
            Map<String, Object> old = cur.get(verb);
            Object locked = lockOps.get(verb);
            if (old == null) {
                entries.add(J.obj("verb", verb, "change", "added"));
                defs.add(d);
            } else if (dg.equals(locked) || (locked == null && Actions.defDigest(old).equals(dg))) {
                entries.add(J.obj("verb", verb, "change", "unchanged"));
                defs.add(old);
            } else {
                Map<String, Object> diff;
                try { diff = ActionDiff.diffDefs(old, d, r, attestationVerified); } catch (RuntimeException ex) { diff = J.obj("class", "incomparable", "reasons", J.list(ex.getMessage())); }
                entries.add(J.obj("verb", verb, "change", "changed", "diff", diff));
                defs.add(d);
            }
        }
        TreeSet<String> deprecated = new TreeSet<>();
        for (String v : lockOps.keySet()) if (!imp.containsKey(v)) deprecated.add(v);
        for (String v : deprecated) entries.add(J.obj("verb", v, "change", "removed"));
        boolean needs = false;
        for (Object e : entries) if ("added".equals(J.get(e, "change")) || "changed".equals(J.get(e, "change"))) needs = true;
        return J.obj("defs", defs, "entries", entries, "deprecated", J.objs(new ArrayList<>(deprecated)), "lock", J.obj("spec_digest", specDigest, "ops", ops, "synced_at", now), "needsReview", needs);
    }

    /** One line per entry, then a summary. */
    public static String syncText(Map<String, Object> r) {
        List<String> lines = new ArrayList<>();
        int added = 0, changed = 0, removed = 0, unchanged = 0;
        for (Object e0 : J.a(r.get("entries"))) {
            String change = (String) J.get(e0, "change");
            switch (change) {
                case "added": added++; break;
                case "changed": changed++; break;
                case "removed": removed++; break;
                default: unchanged++;
            }
            if (change.equals("unchanged")) continue;
            StringBuilder pad = new StringBuilder(change);
            while (pad.length() < 9) pad.append(' ');
            String suffix = "";
            Object diff = J.get(e0, "diff");
            if (diff != null) {
                List<Object> rs = J.a(J.get(diff, "reasons"));
                List<String> rss = new ArrayList<>();
        for (Object x : rs) rss.add(String.valueOf(x));
                suffix = "  (" + J.get(diff, "class") + (rss.isEmpty() ? "" : ": " + String.join(", ", rss)) + ")";
            }
            lines.add(pad + " " + J.get(e0, "verb") + suffix);
        }
        lines.add(added + " added, " + changed + " changed, " + removed + " removed (deprecated), " + unchanged + " unchanged"
            + (Boolean.TRUE.equals(r.get("needsReview")) ? "; added and changed actions are unreviewed (strict) until a reviewer confirms them" : ""));
        return String.join("\n", lines);
    }
}
