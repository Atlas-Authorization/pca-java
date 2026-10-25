package net.atlasauth.pca;

import static net.atlasauth.pca.IntentV2KillTest.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * r9 mutation kills for IntentV2.sessionStep: the revocation set the verifier checks names the standing-profile id exactly
 * when the session root carries a {@code layers.std} layer.
 */
public class K042R9SessionTest {
    private static Function<Map<String, Object>, Pca.Verdict> runner(Map<String, Object> layers) {
        Map<String, Object> body = rootBody();
        body.put("revocation", map("epoch_uri", "https://atlas.example/rev", "max_age_s", 60L, "key", pub(REV)));
        if (layers != null) body.put("layers", layers);
        Map<String, Object> root = signRoot(body, PRINCIPAL);
        String r = IntentSession.rootDigest(root);
        Map<String, Object> g = mint(0, null, MAP0, "salt0", PRINCIPAL, r);
        Map<String, Object> p = build(g, "salt0", MAP0, is0("root", r), params(), REF);
        return ev -> verify(g, p, ctx("session", map("root", root, "grants", list(), "revocation", ev)));
    }

    @Test void standingProfileIdIsCheckedOnlyWhenTheRootNamesOne() {
        Map<String, Object> task = map("map_digest", MAP0);
        // no std layer: the profile id built from the absent layer is not a member of the checked set
        Function<Map<String, Object>, Pca.Verdict> plain = runner(map("task", task));
        String junk = IntentRevocation.profileRevocationId(null, IntentRevocation.jsText(null, true));
        assertTrue(plain.apply(evidence(List.of("pca-intent:zzz"), NOW - 1_000, REV)).allow);
        assertTrue(plain.apply(evidence(List.of(junk), NOW - 1_000, REV)).allow, "an id nobody issued is not checked");
        // a std layer: its profile@version id is checked
        Function<Map<String, Object>, Pca.Verdict> std = runner(map("task", task, "std", map("profile", "std-p", "version", 3L, "digest", SD)));
        assertTrue(std.apply(evidence(List.of("pca-intent:zzz"), NOW - 1_000, REV)).allow);
        assertEquals(List.of("intent_session"), failed(std.apply(evidence(List.of(IntentRevocation.profileRevocationId("std-p", "3")), NOW - 1_000, REV))));
        assertTrue(std.apply(evidence(List.of(IntentRevocation.profileRevocationId("std-p", "4")), NOW - 1_000, REV)).allow);
        assertTrue(std.apply(evidence(List.of(IntentRevocation.profileRevocationId("other", "3")), NOW - 1_000, REV)).allow);
    }

    // ---- OracleFacts.decide: a world counts only the facts NAMED for it ----
    @Test void aWorldDoesNotCountAnotherWorldsFacts() {
        Map<String, Object> fx = IntentWbKillTest.world(1, 0, 60_000L);
        Map<String, Object> gx = new java.util.LinkedHashMap<>(fx);
        gx.put("name", "gx");
        Map<String, Object> pol = map("worlds", list(fx, gx));
        List<Object> facts = list(IntentWbKillTest.fact("fx", "EURUSD", 7L, IntentWbKillTest.NOW, "o1", "wb/o1"));
        OracleFacts.WorldResult r = IntentWbKillTest.decideWorld(facts, pol, IntentWbKillTest.NOW, IntentWbKillTest.action());
        assertFalse(r.ok);
        assertEquals("facts: world 'gx' has 0 fresh fact(s), needs 1", r.reason);
        List<Object> both = list(IntentWbKillTest.fact("fx", "EURUSD", 7L, IntentWbKillTest.NOW, "o1", "wb/o1"), IntentWbKillTest.fact("gx", "EURUSD", 9L, IntentWbKillTest.NOW, "o1", "wb/o1"));
        OracleFacts.WorldResult ok = IntentWbKillTest.decideWorld(both, pol, IntentWbKillTest.NOW, IntentWbKillTest.action());
        assertTrue(ok.ok, ok.reason);
        assertEquals("7", ok.world.get("fx").toString());
        assertEquals("9", ok.world.get("gx").toString());
    }
}
