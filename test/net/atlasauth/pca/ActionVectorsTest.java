package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * Action-kit conformance: every vector of the shared "actions" corpus must reproduce its {@code expect} exactly through
 * {@link Actions} (and the v2 conform path of {@link ActionSchema}). The corpus is read from the monorepo layout or the
 * mirror layout; a missing directory FAILS, it is never skipped.
 */
public class ActionVectorsTest {
    static File dir() {
        for (String p : new String[] {"../../packages/pca-conformance/vectors/actions", "conformance/actions", "../conformance/actions"}) {
            File f = new File(p);
            if (f.isDirectory()) return f;
        }
        throw new AssertionError("the action-kit vectors are missing (a vector directory is never skipped)");
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> cases() throws Exception {
        File[] fs = dir().listFiles((d, n) -> n.endsWith(".json"));
        Arrays.sort(fs);
        List<Map<String, Object>> out = new ArrayList<>();
        for (File f : fs) out.add((Map<String, Object>) IntentJs.normalize(Json.parseLenient(Files.readString(f.toPath(), StandardCharsets.UTF_8))));
        return out;
    }

    @SuppressWarnings("unchecked") static Map<String, Object> M(Object o) { return (Map<String, Object>) o; }

    static Map<String, Object> one(String k, Object v) { Map<String, Object> m = new LinkedHashMap<>(); m.put(k, v); return m; }

    static Map<String, Object> codeOf(String e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", e == null);
        if (e != null) m.put("code", e.split(":")[0].split(" ")[0]);
        return m;
    }

    static Map<String, Object> pins(Map<String, Object> in) { return in.get("pins") == null ? null : M(in.get("pins")); }

    static Actions.Registry registry(Map<String, Object> in) {
        return in.get("custom_traits") != null ? Actions.extendRegistry(Actions.CORE_REGISTRY, (List<Object>) in.get("custom_traits")) : Actions.CORE_REGISTRY;
    }

    @SuppressWarnings("unchecked")
    static Object replay(Map<String, Object> c) {
        Map<String, Object> in = M(c.get("input"));
        switch ((String) c.get("kind")) {
            case "parse": return one("ok", Actions.validateDef(in.get("def")) == null);
            case "digest": {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("digest", Actions.defDigest(M(in.get("def")))); m.put("normalized", Actions.normalize(M(in.get("def"))));
                return m;
            }
            case "effective": {
                Map<String, Object> e = Actions.effective(M(in.get("def")), Actions.CORE_REGISTRY, pins(in)), m = new LinkedHashMap<>();
                m.put("confirmed", e.get("confirmed")); m.put("traits", e.get("traits")); m.put("closure", e.get("closure")); m.put("eff", e.get("eff"));
                return m;
            }
            case "expand": {
                try {
                    Actions.Registry reg = registry(in);
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("closure", new ArrayList<Object>(Actions.closure(reg, (List<Object>) in.get("traits"))));
                    m.put("floor", Actions.floorOf(reg, (List<Object>) in.get("traits")).toMap());
                    return m;
                } catch (Actions.ActionKitError e) { return one("error", Boolean.TRUE); }
            }
            case "schema_verb": {
                try { return codeOf(Actions.schemaVerbFloorError(M(in.get("verb")), registry(in), pins(in))); }
                catch (Actions.ActionKitError e) { return one("error", Boolean.TRUE); }
            }
            case "schema_shape": return one("ok", ActionSchema.shapeError(in.get("doc"), false) == null);
            case "floor": return one("decision", Actions.floorDecision(M(in.get("grant")), M(in.get("call")), Actions.Profile.fromMap(in.get("profile"))));
            case "conform": {
                ActionSchema.Conform r = ActionSchema.conform(in.get("schema"), (String) in.get("verb"), in.get("params"));
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("ok", r.ok);
                if (!r.ok) m.put("code", r.code);
                return m;
            }
            case "pack": {
                List<String> ds = new ArrayList<>();
                for (Object d : (List<?>) in.get("digests")) ds.add((String) d);
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("root", Actions.packRoot(ds)); m.put("proof", Actions.packProof(ds, ds.get((int) IntentJs.lng(in.get("index")))));
                return m;
            }
            case "rule22_schema": { String e = ActionRegistry.rule22Integrity(M(in.get("doc")), pins(in)); Map<String, Object> m = new LinkedHashMap<>(); m.put("ok", e == null); if (e != null) m.put("code", e); return m; }
            case "rule22": {
                String e = ActionRegistry.rule22Integrity(M(in.get("doc")), pins(in));
                Map<String, Object> m = new LinkedHashMap<>();
                if (e != null) { m.put("integrity", e); m.put("decision", "deny"); return m; }
                m.put("integrity", "ok");
                m.put("decision", ActionRegistry.rule22Decide(M(in.get("doc")), (String) in.get("verb"), M(in.get("grant")), (List<Object>) in.get("context")));
                return m;
            }
            case "pack_verify": {
                Map<String, Object> v = ActionRegistry.verifyPack(in.get("pack"), in.get("keys"), in.get("shards") == null ? null : M(in.get("shards")));
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("ok", v.get("ok"));
                if (Boolean.TRUE.equals(v.get("ok"))) { m.put("digest", v.get("digest")); m.put("defs", IntentJs.ofLong(((List<?>) v.get("defs")).size())); }
                return m;
            }
            case "evolution_verify": {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("ok", ActionRegistry.verifyEvolutionRecord(in.get("record"), in.get("keys")) == null);
                String d;
                try { d = ActionRegistry.evolutionDiffDigest(M(in.get("record"))); } catch (RuntimeException e) { d = null; }
                m.put("diff", d);
                return m;
            }
            case "reapproval_verify": return one("ok", ActionRegistry.reapprovalValid(in.get("reapproval"), M(in.get("grant")).get("id"), M(in.get("grant")).get("issuer"), in.get("verb"), in.get("diff")));
            case "pin": {
                Map<String, Object> d = ActionRegistry.decidePin(in);
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("ok", d.get("ok"));
                if (Boolean.TRUE.equals(d.get("ok"))) { m.put("via", d.get("via")); return m; }
                m.put("code", d.get("code")); m.put("escalate", d.get("escalate"));
                if (d.containsKey("needs_reapproval")) m.put("needs_reapproval", d.get("needs_reapproval"));
                return m;
            }
            case "pack_proof_verify": return one("ok", ActionRegistry.verifyPackProof(in.get("root"), in.get("proof"), (String) in.get("digest")));
            case "tracker": {
                ActionRegistry.PackTracker t = new ActionRegistry.PackTracker(in.get("keys"));
                List<Object> out = new ArrayList<>();
                for (Object so : (List<?>) in.get("steps")) {
                    Map<String, Object> r = t.accept(M(so).get("pack"), M(so).get("shards") == null ? null : M(M(so).get("shards")));
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("ok", r.get("ok"));
                    if (Boolean.TRUE.equals(r.get("ok"))) m.put("status", r.get("status")); else m.put("code", r.get("code"));
                    out.add(m);
                }
                return out;
            }
            case "approval_render": {
                try {
                    Map<String, Object> r = Approval.render(M(in.get("def")), in.get("params"), Boolean.TRUE.equals(in.get("confirmed")));
                    String d = Approval.renderDigest(r);
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("ok", true); m.put("render", r); m.put("digest", d); m.put("words", Approval.bindingWords(d));
                    return m;
                } catch (Actions.ActionKitError e) { Map<String, Object> m = new LinkedHashMap<>(); m.put("ok", false); m.put("code", e.code); return m; }
            }
            case "approval_digest": {
                Map<String, Object> m = new LinkedHashMap<>();
                if (Approval.renderShapeError(in.get("render")) != null) { m.put("ok", false); return m; }
                m.put("ok", true); m.put("digest", Approval.renderDigest(in.get("render")));
                return m;
            }
            case "approval_challenge": {
                Map<String, Object> m = new LinkedHashMap<>();
                try { String ch = Approval.challenge(in.get("action_digest"), in.get("render_digest")); m.put("ok", true); m.put("challenge", ch); }
                catch (IllegalArgumentException e) { m.put("ok", false); }
                return m;
            }
            case "approval_escalation": {
                Map<String, Object> b = M(in.get("bind"));
                Escalation.Result r = Escalation.verify(in.get("answer"), (List<?>) in.get("principals"),
                    new Escalation.Binding((String) b.get("policy_digest"), (String) b.get("action_digest"), (String) b.get("history_head"), (String) b.get("render_digest")), IntentJs.lng(in.get("now")));
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("ok", r.ok);
                if (r.ok) m.put("decision", r.decision); else m.put("reason", r.reason);
                return m;
            }
            default: throw new AssertionError("unknown vector kind " + c.get("kind"));
        }
    }

    static Object replayProfile(Map<String, Object> c) {
        Map<String, Object> in = M(c.get("input"));
        Map<String, Object> m = new LinkedHashMap<>();
        try {
            switch ((String) c.get("kind")) {
                case "approval_psd2": m.put("ok", true); m.put("linking", Approval.psd2Linking(M(in.get("render")))); return m;
                case "approval_batch": {
                    Map<String, Object> b = Approval.batch((List<?>) in.get("items"));
                    m.put("ok", true); m.put("batch", b.get("batch")); m.put("action_digest", b.get("action_digest")); m.put("render_digest", b.get("render_digest"));
                    m.put("challenge", b.get("challenge")); m.put("words", b.get("words"));
                    return m;
                }
                default: throw new AssertionError("unknown approval profile vector kind " + c.get("kind"));
            }
        } catch (Actions.ActionKitError e) {
            m.clear(); m.put("ok", false); m.put("code", e.code);
            return m;
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void approvalProfileVectorsReplay() throws Exception {
        File d = null;
        for (String p : new String[] {"../../packages/pca-conformance/vectors/approval-profiles", "conformance/approval-profiles", "../conformance/approval-profiles"}) {
            if (new File(p).isDirectory()) { d = new File(p); break; }
        }
        assertNotNull(d, "the approval profile vectors are missing (a vector directory is never skipped)");
        File[] fs = d.listFiles((x, n) -> n.endsWith(".json"));
        Arrays.sort(fs);
        assertTrue(fs.length >= 12, "approval profile vectors " + fs.length);
        for (File f : fs) {
            Map<String, Object> c = (Map<String, Object>) IntentJs.normalize(Json.parseLenient(Files.readString(f.toPath(), StandardCharsets.UTF_8)));
            assertEquals(Json.canonicalize(c.get("expect")), Json.canonicalize(IntentJs.normalize(replayProfile(c))), (String) c.get("id"));
        }
    }

    @Test
    void everyVectorReplays() throws Exception {
        List<Map<String, Object>> cs = cases();
        assertTrue(cs.size() >= 781, "vector count " + cs.size());
        Map<String, Integer> kinds = new TreeMap<>();
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : cs) {
            kinds.merge((String) c.get("kind"), 1, Integer::sum);
            String want = Json.canonicalize(c.get("expect"));
            String got;
            try { got = Json.canonicalize(IntentJs.normalize(replay(c))); } catch (RuntimeException e) { got = "EXC " + e; }
            if (!want.equals(got)) bad.add(c.get("id") + ":\n  want " + want + "\n  got  " + got);
        }
        if (!bad.isEmpty()) fail(bad.size() + "/" + cs.size() + " mismatches:\n" + String.join("\n", bad.subList(0, Math.min(20, bad.size()))));
        for (String k : new String[] {"parse", "digest", "effective", "expand", "floor", "conform", "pack", "schema_verb", "rule22", "rule22_schema", "schema_shape", "pack_verify", "evolution_verify", "reapproval_verify", "pin", "pack_proof_verify", "tracker", "approval_render", "approval_digest", "approval_challenge", "approval_escalation"}) assertTrue(kinds.getOrDefault(k, 0) >= 8, k);
    }

    @Test
    void pinnedDigests() {
        assertEquals("W2xe4TXZKavAeEpzGVYC8pp-ZhOxDv-_3TF76MveweM", Actions.traitsDigest(Actions.CORE_REGISTRY));
        assertEquals("I7nxRoiVhU18WNY_EaUqegG7KeBYtfP8gMmibsfXJtU", Actions.tablesDigest());
    }

    @Test
    @SuppressWarnings("unchecked")
    void packProofVerifiesAndTamperFails() throws Exception {
        Map<String, Object> c = cases().stream().filter(x -> "pack-builtin".equals(x.get("id"))).findFirst().get();
        List<String> ds = new ArrayList<>();
        for (Object d : (List<?>) M(c.get("input")).get("digests")) ds.add((String) d);
        String root = (String) M(c.get("expect")).get("root");
        for (String d : ds) assertTrue(Actions.verifyPackProof(root, Actions.packProof(ds, d), d));
        assertFalse(Actions.verifyPackProof(root, Actions.packProof(ds, ds.get(0)), ds.get(1)));
    }

    @Test
    @SuppressWarnings("unchecked")
    void wholeDocumentRule22() throws Exception {
        Map<String, Object> c = cases().stream().filter(x -> "schema-verb-adv-honest".equals(x.get("id"))).findFirst().get();
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("verbs", new ArrayList<Object>(List.of(M(c.get("input")).get("verb"))));
        assertNull(Actions.schemaFloorError(doc));
        doc.put("traits_digest", "A".repeat(43));
        assertTrue(Actions.schemaFloorError(doc).startsWith("traits_digest_mismatch"));
    }
}
