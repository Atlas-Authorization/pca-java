package net.atlasauth.pca.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import org.junit.jupiter.api.Test;

/** The conversation recording helpers: which turns are the principal's and which are untrusted tool output (expected values taken from the reference). */
public class MessagesTest {
    private static final class Rec implements Prover {
        final List<String> calls = new ArrayList<>();
        @Override public Proof prove(String verb, String resource, Map<String, Object> params) { throw new UnsupportedOperationException(); }
        @Override public void principal(String text) { calls.add("principal:" + text); }
        @Override public void tool(String name, Object output) { calls.add("tool:" + name + ":" + (output instanceof String ? output : Json.stringify(output))); }
    }

    private static List<String> record(String json) {
        Rec r = new Rec();
        Messages.recordInput(r, Json.parse(json));
        return r.calls;
    }

    @Test void stringAndObjectInputs() {
        assertEquals(List.of("principal:hello"), record("\"hello\""));
        assertEquals(List.of(), record("[\"a\"]"));
        assertEquals(List.of("principal:q"), record("{\"input\":\"q\"}"));
        assertEquals(List.of(), record("5"));
        assertEquals(List.of(), record("null"));
        assertEquals(List.of(), record("{}"));
        assertEquals(List.of("principal:in-array", "principal:qq", "principal:m", "principal:t"), record("{\"query\":[\"x\",{\"role\":\"user\",\"content\":\"in-array\"}],\"question\":\"qq\",\"text\":\"t\",\"message\":\"m\"}"));
    }

    @Test void rolesDecideWhoSpoke() {
        assertEquals(List.of("principal:hi", "tool:search:result", "principal:p"),
            record("{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"},{\"role\":\"assistant\",\"content\":\"yo\"},{\"role\":\"tool\",\"name\":\"search\",\"content\":\"result\"}],\"prompt\":\"p\"}"));
        assertEquals(List.of("principal:h", "tool:f:{\"a\":1}", "tool:tool:w", "principal:", "principal:{\"a\":1}"),
            record("[{\"role\":\"system\",\"content\":\"s\"},{\"role\":\"developer\",\"content\":\"d\"},{\"type\":\"human\",\"content\":\"h\"},{\"type\":\"ai\",\"content\":\"x\"},{\"role\":\"function\",\"name\":\"f\",\"content\":{\"a\":1}},{\"role\":\"weird\",\"content\":\"w\"},{\"role\":\"user\"},null,5,{\"role\":\"user\",\"content\":{\"a\":1}}]"));
        assertEquals(List.of("principal:upper"), record("[{\"role\":\"USER\",\"content\":\"upper\"}]"));
    }

    @Test void partsOfAUserTurn() {
        assertEquals(List.of("principal:a\nb", "tool:t1:out", "principal:{\"type\":\"image\",\"data\":1}"),
            record("[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"a\"},{\"type\":\"text\",\"text\":\"b\"},{\"type\":\"tool_result\",\"tool_use_id\":\"t1\",\"content\":\"out\"},{\"type\":\"image\",\"data\":1}]}]"));
        assertEquals(List.of("principal:plain\n3\nnull"), record("[{\"role\":\"user\",\"content\":[\"plain\",3,null]}]"));
    }

    @Test void alreadyRecordedMessagesAreSkipped() {
        Rec r = new Rec();
        List<?> list = (List<?>) Json.parse("[{\"role\":\"user\",\"content\":\"one\"},{\"role\":\"tool\",\"name\":\"x\",\"content\":\"two\"},{\"role\":\"user\",\"content\":\"three\"}]");
        Messages.recordMessages(r, list.subList(0, 2));
        Messages.recordMessages(r, list);
        Messages.recordMessages(r, list.subList(0, 1)); // a shorter list starts over
        assertEquals(List.of("principal:one", "tool:x:two", "principal:three", "principal:one"), r.calls);
    }

    @Test void wrapperRecordsBeforeItRuns() {
        Rec r = new Rec();
        List<String> order = new ArrayList<>();
        String out = Messages.<Object, String>withPrincipalInput(r, in -> { order.addAll(r.calls); return "done"; }).apply("ask");
        assertEquals("done", out);
        assertEquals(List.of("principal:ask"), order);
        assertTrue(Messages.messageSegments(5).isEmpty());
    }

    @Test void wrapsAModelCallThatTakesMessages() {
        Rec r = new Rec();
        Map<String, Object> req = (Map<String, Object>) Json.parse("{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}");
        List<String> seen = new ArrayList<>();
        String out = Messages.<String>withPcaCompletions(r, p -> { seen.addAll(r.calls); return "ok"; }).apply(req);
        assertEquals("ok", out);
        assertEquals(List.of("principal:hello"), seen, "recorded before the call ran");
        Messages.<String>withPcaMessages(r, p -> "x").apply(Map.of("model", "m")); // no messages: nothing recorded
        assertEquals(List.of("principal:hello"), r.calls);
    }
}
