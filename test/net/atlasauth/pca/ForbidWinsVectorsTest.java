package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The forbid-wins decision and certificate (forbid-certificate-vectors.json): every decide row replayed with the evaluators, every table row with the consistency rule. */
public class ForbidWinsVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("forbid-certificate-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static List<String> strs(Object o) {
        if (o == null) return null;
        List<String> out = new ArrayList<>();
        for (Object x : l(o)) out.add((String) x);
        return out;
    }

    @Test void everyDecideRowReproducesTheReference() {
        List<Object> rows = l(DOC.get("decide"));
        assertTrue(rows.size() >= 11, "decide rows: " + rows.size());
        for (Object x : rows) {
            Map<String, Object> r = m(x);
            String name = (String) r.get("name");
            Map<String, Object> opts = r.get("options") == null ? new LinkedHashMap<>() : m(r.get("options"));
            ForbidWins.Decision d = ForbidWins.decide(r.get("clauses"), m(r.get("action")), strs(opts.get("precedence")), strs(opts.get("permitSigners")));
            Map<String, Object> exp = m(r.get("expect"));
            assertEquals(exp.get("decision"), d.decision, name + ": decision");
            assertEquals(m(exp.get("winner")).get("kind"), d.winnerKind, name + ": winner kind");
            assertEquals(m(exp.get("winner")).get("id"), d.winnerId, name + ": winner id");
            assertEquals(l(exp.get("shadowed")), new ArrayList<Object>(d.shadowed), name + ": shadowed");
            assertEquals(Json.canonicalize(exp.get("values")), Json.canonicalize(new ArrayList<Object>(d.values)), name + ": values");
            Map<String, Object> cert = ForbidWins.certify(r.get("clauses"), m(r.get("action")), strs(opts.get("precedence")), strs(opts.get("permitSigners")));
            assertEquals(exp.get("certificate_digest"), Pca.hashCanonical(cert), name + ": certificate digest");
            assertNull(ForbidWins.check(cert, r.get("clauses"), m(r.get("action")), strs(opts.get("precedence")), strs(opts.get("permitSigners"))), name + ": a recomputed certificate is accepted");
        }
    }

    @Test void everyTableRowReproducesTheReference() {
        List<Object> rows = l(DOC.get("table"));
        assertTrue(rows.size() >= 19, "table rows: " + rows.size());
        for (Object x : rows) {
            Map<String, Object> r = m(x);
            Map<String, Object> opts = r.get("options") == null ? new LinkedHashMap<>() : m(r.get("options"));
            assertEquals(m(r.get("expect")).get("consistent"), ForbidWins.consistent(r.get("certificate"), strs(opts.get("precedence"))), (String) r.get("name"));
        }
    }

    @Test void aTamperedCertificateOrMalformedClausesAreRefused() {
        Map<String, Object> r = m(l(DOC.get("decide")).get(0));
        Map<String, Object> action = m(r.get("action"));
        Map<String, Object> cert = ForbidWins.certify(r.get("clauses"), action, null, null);
        Map<String, Object> other = new LinkedHashMap<>(action);
        Map<String, Object> inner = new LinkedHashMap<>(m(action.get("action")));
        inner.put("resource", "/acct/2");
        other.put("action", inner);
        assertEquals("certificate does not match the recomputed decision", ForbidWins.check(cert, r.get("clauses"), other, null, null));
        assertEquals("malformed clauses", ForbidWins.check(cert, "x", action, null, null));
        assertEquals("malformed", ForbidWins.decide(new ArrayList<>(List.of("x")), action, null, null).winnerKind);
        assertEquals("malformed", ForbidWins.decide(r.get("clauses"), new LinkedHashMap<>(), null, null).winnerKind);
        assertEquals("clauses must be an array", ForbidWins.clausesError(null));
    }
}
