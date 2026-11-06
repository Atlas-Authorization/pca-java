package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import net.atlasauth.pca.servlet.PcaCore;

/** The HTTP status and body PcaCore gives each execution outcome. */
public class OperationHttpKillTest {
    static Operations.ExecuteOutcome out(String status, Object result, boolean hasResult) {
        return new Operations.ExecuteOutcome(status, "op1", result, hasResult, "boom", "why", false, true, null);
    }

    @Test void statusPerOutcome() {
        assertEquals(403, PcaCore.operationStatus(null));
        assertEquals(200, PcaCore.operationStatus(out(Operations.ExecuteOutcome.COMMITTED, null, false)));
        assertEquals(500, PcaCore.operationStatus(out(Operations.ExecuteOutcome.FAILED, null, false)));
        assertEquals(409, PcaCore.operationStatus(out(Operations.ExecuteOutcome.ABORTED, null, false)));
        assertEquals(409, PcaCore.operationStatus(out(Operations.ExecuteOutcome.PENDING, null, false)));
        assertEquals(409, PcaCore.operationStatus(out(Operations.ExecuteOutcome.UNCERTAIN, null, false)));
        assertEquals(403, PcaCore.operationStatus(out(Operations.ExecuteOutcome.REFUSED, null, false)));
        assertEquals(403, PcaCore.operationStatus(out(Operations.ExecuteOutcome.DENIED, null, false)));
    }

    @Test void bodyPerOutcome() {
        assertEquals("{\"status\":\"refused\"}", PcaCore.operationBody(null));
        assertEquals("{\"reason\":\"no\",\"status\":\"refused\"}", PcaCore.operationBody(Operations.ExecuteOutcome.refused("no")));
        assertEquals("{\"operationId\":\"op1\",\"recorded\":true,\"replayed\":false,\"result\":\"r\",\"status\":\"committed\"}",
            PcaCore.operationBody(out(Operations.ExecuteOutcome.COMMITTED, "r", true)));
        // a result that is not JSON is left out; the rest of the outcome is still written
        assertEquals("{\"operationId\":\"op1\",\"recorded\":true,\"replayed\":false,\"status\":\"committed\"}",
            PcaCore.operationBody(out(Operations.ExecuteOutcome.COMMITTED, new Object(), true)));
    }
}
