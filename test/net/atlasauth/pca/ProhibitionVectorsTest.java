package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** prohibition-vectors.json: the forbid-wins clause validation and decision (`clauses`) and the certificate recomputation (`check`). */
public class ProhibitionVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("prohibition-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static List<String> strs(Object o) {
        if (o == null) return null;
        List<String> out = new ArrayList<>();
        for (Object x : l(o)) out.add((String) x);
        return out;
    }

    @Test void everyClausesRowReproducesTheReference() {
        List<Object> rows = l(DOC.get("clauses"));
        assertTrue(rows.size() >= 20, "clauses rows: " + rows.size());
        for (Object x : rows) {
            Map<String, Object> r = m(x);
            String name = (String) r.get("name");
            Map<String, Object> exp = m(r.get("expect"));
            Map<String, Object> action = r.get("action") instanceof Map ? m(r.get("action")) : null;
            assertEquals(exp.get("error"), ForbidWins.clausesError(r.get("clauses")), name + ": error");
            ForbidWins.Decision d = ForbidWins.decide(r.get("clauses"), action, null, null);
            assertEquals(exp.get("decision"), d.decision, name + ": decision");
            assertEquals(m(exp.get("winner")).get("kind"), d.winnerKind, name + ": winner kind");
            assertEquals(m(exp.get("winner")).get("id"), d.winnerId, name + ": winner id");
            assertEquals(l(exp.get("shadowed")), new ArrayList<Object>(d.shadowed), name + ": shadowed");
            assertEquals(Json.canonicalize(exp.get("values")), Json.canonicalize(new ArrayList<Object>(d.values)), name + ": values");
        }
    }

    @Test void everyCheckRowReproducesTheReference() {
        List<Object> rows = l(DOC.get("check"));
        assertTrue(rows.size() >= 11, "check rows: " + rows.size());
        for (Object x : rows) {
            Map<String, Object> r = m(x);
            String name = (String) r.get("name");
            Map<String, Object> opts = r.get("options") == null ? new LinkedHashMap<>() : m(r.get("options"));
            Map<String, Object> action = r.get("action") instanceof Map ? m(r.get("action")) : null;
            String why = ForbidWins.check(r.get("certificate"), r.get("clauses"), action, strs(opts.get("precedence")), strs(opts.get("permitSigners")));
            Map<String, Object> exp = m(r.get("expect"));
            assertEquals(exp.get("ok"), why == null, name + ": ok (" + why + ")");
            if (!Boolean.TRUE.equals(exp.get("ok"))) assertEquals(exp.get("reason"), why, name + ": reason");
        }
    }

    static Map<String, Object> state(Object s) { return m(s); }

    @Test void everyConstitutionRowReproducesTheReference() {
        List<Object> rows = l(DOC.get("constitution"));
        assertTrue(rows.size() >= 33, "constitution rows: " + rows.size());
        for (Object x : rows) {
            Map<String, Object> r = m(x);
            String name = (String) r.get("name");
            Map<String, Object> exp = m(r.get("expect"));
            assertEquals(l(exp.get("problems")), new ArrayList<Object>(Prohibitions.validateConstitution(r.get("constitution"))), name + ": problems");
            Map<String, Object> got = Prohibitions.checkProhibitions(r.get("action"), r.get("constitution"), r.get("state"));
            assertEquals(Json.canonicalize(exp.get("result")), Json.canonicalize(got), name + ": result");
        }
    }

    @Test void everyMonitorSequenceReproducesTheReference() {
        List<Object> rows = l(DOC.get("monitor"));
        assertTrue(rows.size() >= 5, "monitor rows: " + rows.size());
        for (Object x : rows) {
            Map<String, Object> r = m(x);
            String name = (String) r.get("name");
            Object constitution = r.get("constitution");
            Object st = Prohibitions.emptyState(r.get("genesis_now"));
            int i = 0;
            for (Object sx : l(r.get("steps"))) {
                Map<String, Object> step = m(sx);
                Map<String, Object> exp = m(step.get("expect"));
                String label = name + " step " + i++;
                if (step.containsKey("now")) {
                    Map<String, Object> tick = Prohibitions.tickState(st, step.get("now"));
                    if (!Boolean.TRUE.equals(tick.get("ok"))) {
                        assertEquals(false, exp.get("allow"), label);
                        assertEquals("clock", exp.get("decidedBy"), label);
                        assertEquals(exp.get("reason"), tick.get("reason"), label);
                        continue;
                    }
                    st = tick.get("state");
                }
                Map<String, Object> res = Prohibitions.checkAndAdvance(true, step.get("action"), constitution, st, null, null);
                assertEquals(exp.get("allow"), res.get("allow"), label + ": allow");
                assertEquals(exp.get("decidedBy"), res.get("decidedBy"), label + ": decidedBy");
                assertEquals(l(exp.get("violated")), new ArrayList<Object>(l(m(res.get("prohibition")).get("violated"))), label + ": violated");
                if (Boolean.TRUE.equals(res.get("allow"))) st = res.get("next");
                if (exp.containsKey("seq")) assertEquals(Prohibitions.dv(exp.get("seq")), Prohibitions.dv(m(st).get("seq")), label + ": seq");
            }
        }
    }

    @Test void everyEvidenceRowReproducesTheReference() {
        List<Object> rows = l(DOC.get("evidence"));
        assertTrue(rows.size() >= 13, "evidence rows: " + rows.size());
        for (Object x : rows) {
            Map<String, Object> r = m(x);
            String name = (String) r.get("name");
            Map<String, Object> exp = m(r.get("expect"));
            String why = Prohibitions.verifySignedSafetyEvidence(r.get("signed"), r.get("expected"));
            assertEquals(exp.get("ok"), why == null, name + ": ok (" + why + ")");
            if (!Boolean.TRUE.equals(exp.get("ok"))) assertEquals(exp.get("reason"), why, name + ": reason");
        }
    }
}
