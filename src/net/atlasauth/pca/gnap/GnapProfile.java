package net.atlasauth.pca.gnap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Issue;

/** The Agent-GNAP profile as a machine-readable spec object. */
final class GnapProfile {
    private GnapProfile() {}

    private static Map<String, Object> obj(Object... kv) { return Issue.obj(kv); }

    private static List<Object> lst(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    static Map<String, Object> profile() {
        return obj(
            "name", "agent-gnap",
            "version", "1.0",
            "rfc", "RFC 9635",
            "summary", "A GNAP profile for autonomous-agent delegation: each A2A hop is a GNAP grant whose authority is issued as an attenuated, key-bound PCA capability, never wider than the issuing agent.",
            "mapping", lst(
                    obj(
                            "gnap", "access[].type",
                            "pca", "predicate resource namespace gnap:<type>:<location>",
                            "note", "the resource family the rights live in"),
                    obj(
                            "gnap", "access[].actions",
                            "pca", "predicate.verb (list, or * for any)",
                            "note", "the operations permitted"),
                    obj(
                            "gnap", "access[].locations",
                            "pca", "predicate.resource (exact or trailing-* prefix)",
                            "note", "the resource targets"),
                    obj(
                            "gnap", "access[].datatypes / identifier",
                            "pca", "predicate.where on action.params.*",
                            "note", "value-level constraints"),
                    obj(
                            "gnap", "client.key.jwk (OKP/Ed25519)",
                            "pca", "capability.holder (cnf-bound key)",
                            "note", "the proof-of-possession key"),
                    obj(
                            "gnap", "grant request (no prior grant)",
                            "pca", "mintGrant \u2192 root capability",
                            "note", "envelope predicates = requested access"),
                    obj(
                            "gnap", "grant request (delegated hop)",
                            "pca", "delegate \u2192 child capability + gnap_access caveat",
                            "note", "append-only attenuation"),
                    obj(
                            "gnap", "access_token (\u00a73.2)",
                            "pca", "a verifiable PCA capability chain (encodeBoundToken)",
                            "note", "bound, self-verifying token"),
                    obj(
                            "gnap", "continue (\u00a73.1) + interact (\u00a73.3)",
                            "pca", "PCA step-up: FROST/threshold co-signature folded into a PCActn",
                            "note", "tier-2/3 escalation"),
                    obj(
                            "gnap", "jwsd detached JWS (\u00a77.3.4)",
                            "pca", "request proof binding the body to capability.holder",
                            "note", "verified with jose")),
            "proofMethods", lst(
                    "jwsd"),
            "multiHop", "An A2A task is a chain of GNAP grants. Each hop delegates from the issuing agent to the next, recording its (clamped) rights as an append-only gnap_access caveat. Effective authority is the intersection of the root policy envelope and every hop; PCA caveats are conjunctive and append-only, so no hop can widen \u2014 \"never wider than the issuer\" holds across any depth.",
            "stepUp", "A request for authority beyond the issuer (or an explicit interaction) returns a GNAP continue handle instead of a token. The client returns with the action PCActn plus a guardian/principal co-signature, which is folded into the PCActn threshold and verified at tier 2/3 (FROST or multi-signature) before the action is admitted.",
            "security", lst(
                    "Attenuation is structural and append-only: a delegated hop can only ever narrow authority.",
                    "Every grant is key-bound (cnf): the holder key must prove possession via a jwsd detached JWS.",
                    "All verification fails closed: bad token, broken chain, bad proof, stale request, or out-of-scope action denies.",
                    "Rights beyond the issuer are clamped at issue time and denied at action time (defense in depth).",
                    "Elevation beyond the agent requires a human/guardian co-signature, not a self-minted grant."));
    }
}
