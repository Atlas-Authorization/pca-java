package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.a2a.A2aPca;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the A2A adapter through the native port. */
public class A2aDiffTest {
    private static final String M = "ref-a2a";
    private static final Pattern LIB_REASON = Pattern.compile("^(signature \\d+ did not verify|could not resolve verification key|malformed payment mandate or PCActn): ");

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<String> strs(Object o) { return (List<String>) o; }

    /** Reasons that quote the JOSE library, or a runtime message, are compared up to the first colon. */
    private static Object norm(Map<String, Object> r) {
        Object reason = r.get("reason");
        if (reason instanceof String) {
            Matcher mt = LIB_REASON.matcher((String) reason);
            if (mt.find()) { Map<String, Object> c = new LinkedHashMap<>(r); c.put("reason", mt.group(1)); return c; }
        }
        return r;
    }

    private static A2aPca.VerifyOptions opts(Object o) {
        Map<String, Object> x = m(o);
        A2aPca.VerifyOptions v = new A2aPca.VerifyOptions();
        v.aud = (String) x.get("aud");
        if (x.get("now") != null) v.now = Json.asLong(x.get("now"));
        v.grant = x.get("grant") == null ? null : m(x.get("grant"));
        v.expectedRootIssuer = (String) x.get("expectedRootIssuer");
        v.requireProof = !Boolean.FALSE.equals(x.get("require"));
        if (x.get("humanSignerSet") instanceof List) { @SuppressWarnings("unchecked") List<Object> l = (List<Object>) x.get("humanSignerSet"); v.humanSignerSet = l; }
        if (x.containsKey("context")) { final Map<String, Object> ctx = m(x.get("context")); v.context = p -> ctx; }
        return v;
    }

    private static byte[] seed(String label) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8));
    }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("PCA_A2A_EXTENSION_URI", A2aPca.PCA_A2A_EXTENSION_URI);
            o.put("TASK_STATE_AUTH_REQUIRED", A2aPca.TASK_STATE_AUTH_REQUIRED);
            o.put("TASK_STATE_INPUT_REQUIRED", A2aPca.TASK_STATE_INPUT_REQUIRED);
            o.put("A2A_AP2_CONTEXT", new ArrayList<Object>(A2aPca.A2A_AP2_CONTEXT));
            o.put("A2A_RECEIPT_DOMAIN", A2aPca.A2A_RECEIPT_DOMAIN);
            o.put("RECEIPT_KEY", A2aPca.RECEIPT_KEY);
            return o;
        });
    }

    @Test void jcsBytes() throws Exception { OracleCases.each(M, "jcsBytes", a -> A2aPca.jcsBytes(a.get(0))); }
    @Test void validateAgentCard1() throws Exception { OracleCases.each(M, "validateAgentCard1", a -> A2aPca.validateAgentCard1(a.get(0))); }
    @Test void attachPcaToA2ATask() throws Exception { OracleCases.each(M, "attachPcaToA2ATask", a -> A2aPca.attachPcaToA2ATask(a.get(0), a.get(1))); }
    @Test void attachPcaToA2AMessage() throws Exception { OracleCases.each(M, "attachPcaToA2AMessage", a -> A2aPca.attachPcaToA2AMessage(a.get(0), a.get(1))); }
    @Test void extractPca() throws Exception { OracleCases.each(M, "extractPca", a -> A2aPca.extractPca(a.get(0))); }
    @Test void extractPcaFromMessage() throws Exception { OracleCases.each(M, "extractPcaFromMessage", a -> A2aPca.extractPcaFromMessage(a.get(0))); }

    @Test void verifyA2ATask() throws Exception { OracleCases.each(M, "verifyA2ATask", a -> A2aPca.verifyA2ATask(a.get(0), opts(a.get(1))).toMap()); }
    @Test void middleware() throws Exception { OracleCases.each(M, "middleware", a -> A2aPca.pcaA2AMiddleware(opts(a.get(1))).check(a.get(0)).toMap()); }
    @Test void resumeAuthRequired() throws Exception { OracleCases.each(M, "resumeAuthRequired", a -> A2aPca.resumeAuthRequired(a.get(0), a.get(1), opts(a.get(2)))); }

    @Test void authRequiredStatus() throws Exception {
        OracleCases.each(M, "authRequiredStatus", a -> {
            Map<String, Object> o = m(a.get(1));
            return A2aPca.authRequiredStatus(m(a.get(0)), o.get("messageId"), o.get("now"), (String) o.get("text"));
        });
    }

    @Test void answerMessage() throws Exception { OracleCases.each(M, "answerMessage", a -> A2aPca.answerMessage(a.get(0), a.get(1), a.get(2))); }
    @Test void readAuthRequiredNeed() throws Exception { OracleCases.each(M, "readAuthRequiredNeed", a -> A2aPca.readAuthRequiredNeed(a.get(0))); }
    @Test void isAuthRequired() throws Exception { OracleCases.each(M, "isAuthRequired", a -> A2aPca.isAuthRequired(a.get(0))); }

    @Test void resumeGate() throws Exception {
        OracleCases.each(M, "resumeGate", a -> {
            Map<String, Object> x = m(a.get(0));
            return A2aPca.resumeGate(x.get("state"), x.get("needEncoded"), x.get("answerNeedDigest"), x.containsKey("proofAction") ? x.get("proofAction") : A2aPca.NO_PROOF);
        });
    }

    @Test void pcaExtensionDeclaration() throws Exception {
        OracleCases.each(M, "pcaExtensionDeclaration", a -> a.size() > 1 ? A2aPca.pcaExtensionDeclaration(a.get(0), (Boolean) a.get(1)) : A2aPca.pcaExtensionDeclaration(a.get(0)));
    }
    @Test void readPcaExtension() throws Exception { OracleCases.each(M, "readPcaExtension", a -> A2aPca.readPcaExtension(a.get(0))); }
    @Test void clientOptsIntoPca() throws Exception { OracleCases.each(M, "clientOptsIntoPca", a -> A2aPca.clientOptsIntoPca(a.get(0))); }
    @Test void checkChainExtension() throws Exception { OracleCases.each(M, "checkChainExtension", a -> A2aPca.checkChainExtension(a.get(0))); }
    @Test void chainExtends() throws Exception { OracleCases.each(M, "chainExtends", a -> A2aPca.chainExtends((List<?>) a.get(0), (List<?>) a.get(1))); }

    @Test void verifyA2ADelegation() throws Exception {
        OracleCases.each(M, "verifyA2ADelegation", a -> {
            List<A2aPca.Hop> hops = new ArrayList<>();
            for (Object h : (List<?>) a.get(0)) hops.add(new A2aPca.Hop(m(h).get("task"), opts(m(h).get("opts"))));
            return A2aPca.verifyA2ADelegation(hops);
        });
    }

    @Test void pcaPushToken() throws Exception { OracleCases.each(M, "pcaPushToken", a -> A2aPca.pcaPushToken(a.get(0), strs(a.get(1)), a.get(2))); }

    @Test void checkPushNotification() throws Exception {
        OracleCases.each(M, "checkPushNotification", a -> {
            Map<String, Object> e = m(a.get(0)), d = m(a.get(1));
            return A2aPca.checkPushNotification((String) e.get("taskId"), strs(e.get("chainIds")), e.get("salt"), d.get("token"), d.get("payload"));
        });
    }

    @Test void uniformTaskNotFound() throws Exception { OracleCases.each(M, "uniformTaskNotFound", a -> A2aPca.uniformTaskNotFound()); }

    @Test void signTaskReceipt() throws Exception {
        OracleCases.each(M, "signTaskReceipt", a -> {
            Map<String, Object> o = m(a.get(1));
            return A2aPca.signTaskReceipt(seed((String) a.get(0)), o.get("taskId"), o.get("state"), strs(o.get("chainIds")), o.get("issuedAt"), o.get("prev") == null ? null : m(o.get("prev")));
        });
    }

    @Test void verifyTaskReceipt() throws Exception { OracleCases.each(M, "verifyTaskReceipt", a -> A2aPca.verifyTaskReceipt(a.get(0), (String) a.get(1))); }
    @Test void receiptDigest() throws Exception { OracleCases.each(M, "receiptDigest", a -> A2aPca.receiptDigest(a.get(0))); }

    @Test void checkReceiptChain() throws Exception {
        OracleCases.each(M, "checkReceiptChain", a -> {
            Map<String, Object> o = m(a.get(1));
            return A2aPca.checkReceiptChain(a.get(0), (String) o.get("signer"), (String) o.get("taskId"), strs(o.get("chainIds")));
        });
    }

    @Test void mayTriggerNext() throws Exception {
        OracleCases.each(M, "mayTriggerNext", a -> {
            Map<String, Object> o = m(a.get(1));
            return A2aPca.mayTriggerNext(a.get(0), (String) o.get("signer"), (String) o.get("taskId"), strs(o.get("chainIds")));
        });
    }

    @Test void attachReceipt() throws Exception { OracleCases.each(M, "attachReceipt", a -> A2aPca.attachReceipt(a.get(0), a.get(1))); }
    @Test void receiptOfPayload() throws Exception { OracleCases.each(M, "receiptOfPayload", a -> A2aPca.receiptOfPayload(a.get(0))); }
    @Test void extendedAgentCard() throws Exception { OracleCases.each(M, "extendedAgentCard", a -> A2aPca.extendedAgentCard(a.get(0), m(a.get(1)))); }

    @Test void issueSignedAgentCard() throws Exception {
        OracleCases.each(M, "issueSignedAgentCard", a -> {
            A2aPca.IssueOptions io = new A2aPca.IssueOptions();
            if (a.size() > 2) {
                Map<String, Object> o = m(a.get(2));
                io.alg = (String) o.get("alg");
                io.kid = (String) o.get("kid");
                io.profile = (String) o.get("profile");
                io.schema = (String) o.get("schema");
                io.passport = o.get("passport") == null ? null : m(o.get("passport"));
            }
            return A2aPca.issueSignedAgentCard(a.get(0), m(a.get(1)), io);
        });
    }

    @Test void verifyAgentCard() throws Exception {
        OracleCases.each(M, "verifyAgentCard", a -> {
            Map<String, Object> o = m(a.get(1));
            A2aPca.VerifyCardOptions vo = new A2aPca.VerifyCardOptions();
            vo.jwks = o.get("jwks");
            vo.key = o.get("key");
            vo.alg = (String) o.get("alg");
            vo.schema = (String) o.get("schema");
            return norm(A2aPca.verifyAgentCard(a.get(0), vo));
        });
    }

    @Test void a2aPaymentMandateFromPca() throws Exception { OracleCases.each(M, "a2aPaymentMandateFromPca", a -> A2aPca.a2aPaymentMandateFromPca(a.get(0), m(a.get(1)))); }
    @Test void pcaBindingFromA2APaymentMandate() throws Exception { OracleCases.each(M, "pcaBindingFromA2APaymentMandate", a -> A2aPca.pcaBindingFromA2APaymentMandate(a.get(0))); }

    @Test void verifyA2APaymentMandate() throws Exception {
        OracleCases.each(M, "verifyA2APaymentMandate", a -> norm(A2aPca.verifyA2APaymentMandate(a.get(0), a.get(1), opts(a.get(2))).toMap()));
    }

    /** What the oracle cannot cover: a PCActn that reaches the verifier is refused without a revocation predicate, and a plug-in verifier decides. */
    @Test void verifierPlugAndDefaultRevocation() {
        Map<String, Object> pca = new LinkedHashMap<>();
        Map<String, Object> cap = new LinkedHashMap<>();
        cap.put("id", "g1");
        cap.put("issuer", "ROOT");
        cap.put("holder", "H1");
        pca.put("cap_chain", new ArrayList<Object>(List.of(cap)));
        Map<String, Object> task = new LinkedHashMap<>();
        Map<String, Object> md = new LinkedHashMap<>();
        md.put(A2aPca.PCA_A2A_EXTENSION_URI, pca);
        task.put("metadata", md);
        A2aPca.VerifyOptions o = new A2aPca.VerifyOptions();
        o.aud = "rs";
        o.now = 1L;
        o.expectedRootIssuer = "ROOT";
        org.junit.jupiter.api.Assertions.assertFalse(A2aPca.verifyA2ATask(task, o).ok); // the core verifier refuses a PCActn with no signature
        o.verifier = (p, r) -> new A2aPca.Outcome(true, new LinkedHashMap<>(), new ArrayList<>());
        org.junit.jupiter.api.Assertions.assertTrue(A2aPca.verifyA2ATask(task, o).ok);
        o.verifier = (p, r) -> { throw new IllegalStateException("boom"); };
        org.junit.jupiter.api.Assertions.assertFalse(A2aPca.verifyA2ATask(task, o).ok); // a throwing verifier is a refusal
    }
}
