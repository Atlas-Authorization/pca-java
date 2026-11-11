package net.atlasauth.pca.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import net.atlasauth.pca.Authorize;

/** 0.5 mutation survivors of PcaResult (shard 10): the status of an allow and the description of an authorize denial. */
public class ServletK05bKillTest {
    static final String AUD = PcaCoreKillTest.AUD;
    static final long NOW = PcaCoreKillTest.NOW;

    @Test void anAllowedAuthorizeDecisionKeepsTheNonDenialStatus() {
        PcaResult ok = PcaCore.authorize(PcaCoreKillTest.action(), null, AUD, NOW, PcaCoreKillTest.RES, PcaCoreKillTest.opts(), PcaCoreKillTest.op());
        assertTrue(ok.allowed(), ok.detail());
        assertNotNull(ok.authorization());
        assertEquals(200, ok.authorization().status);
        // status() answers a refusal: 403 for a denial, 401 otherwise; an allow never reports the decision's own status
        assertEquals(401, ok.status());
        assertNull(ok.error());
    }

    /** The {@code ,"error_description":"..."} member jsonBody writes for {@code desc}. */
    static String descriptionMember(String desc) {
        String b = new PcaResult(PcaResult.Outcome.DENIED, null, null, desc).jsonBody();
        return b.substring(b.indexOf(",\"error_description\":"), b.length() - 1);
    }

    @Test void anAuthorizeDenialIsDescribedByItsOwnReasonNotTheCoreVerdicts() {
        // wrong audience (the core verdict's first failure) and another resource (the decisive operation failure)
        Authorize.Operation fixture = PcaCoreKillTest.op();
        Authorize.Operation other = Authorize.Operation.of(fixture.verb, fixture.resource + "/other", fixture.params);
        PcaResult r = PcaCore.authorize(PcaCoreKillTest.action(), null, "another-audience", NOW, PcaCoreKillTest.RES, PcaCoreKillTest.opts(), other);
        assertEquals(PcaResult.Outcome.DENIED, r.outcome());
        assertNotNull(r.verdict());
        String core = r.verdict().reason, own = r.authorization().reason;
        assertNotNull(core);
        assertFalse(core.isEmpty());
        assertNotEquals(core, own);
        assertEquals(own, r.detail());
        assertTrue(r.jsonBody().contains(descriptionMember(own)), r.jsonBody());
        assertFalse(r.jsonBody().contains(descriptionMember(core)), r.jsonBody());
    }
}
