package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** 0.5 mutation kills for {@link Refusals}: the leading-check match decides before the "name:" fallback scan. */
public class RefusalsRestKillTest {
    @Test void refusalsHeadMatch() {
        assertEquals("replay", Refusals.explain("replay").check());
        assertEquals("replay", Refusals.explain("replay x").check());
        assertEquals("grant_ref_bound", Refusals.explain("grant_ref_bound").check());
        assertEquals("audience", Refusals.explain("audience").check());
        assertEquals("unknown", Refusals.explain("replayz x").check());
        assertEquals("replay", Refusals.explain("replay{ x").check());
        assertEquals("template", Refusals.explain("template: audience: x").check());
        assertEquals("unknown", Refusals.explain("Replay").check());
    }
}
