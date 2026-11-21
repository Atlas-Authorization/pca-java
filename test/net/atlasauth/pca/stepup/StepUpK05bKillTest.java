package net.atlasauth.pca.stepup;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** 0.5 mutation survivor of StepUpClient.call (shard 10): only a string error message replaces the generic one. */
public class StepUpK05bKillTest {
    @Test void aNullOrMissingErrorMessageKeepsTheGenericOne() {
        for (String body : new String[] {"{\"errors\":[{\"message\":null}]}", "{\"errors\":[{}]}"}) {
            StepUpException.ApiError a = assertThrows(StepUpException.ApiError.class,
                StepUpKillTest.client(new StepUpKillTest.Fake(new StepUpClient.Response(500, body)))::pending);
            assertEquals(500, a.status);
            assertEquals("The request failed.", a.getMessage(), body);
            StepUpException.PrincipalMismatch m = assertThrows(StepUpException.PrincipalMismatch.class,
                StepUpKillTest.client(new StepUpKillTest.Fake(new StepUpClient.Response(403, body)))::pending);
            assertEquals("The request failed.", m.getMessage(), body);
        }
    }
}
