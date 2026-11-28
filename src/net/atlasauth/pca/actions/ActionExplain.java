package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import net.atlasauth.pca.Actions;

/** The plain-language profile of one def: its policy card, the effective profile, and what a grant must carry before the action is auto-allowed. Deterministic text. */
public final class ActionExplain {
    private ActionExplain() {}

    private static String blastText(long ppm) { return ppm % 1000 == 0 ? (ppm / 1000) + "k" : ppm + "ppm"; }

    private static String join(Object xs) {
        List<String> l = new ArrayList<>();
        for (Object x : J.a(xs)) l.add((String) x);
        return String.join(", ", l);
    }

    public static String explainDef(Map<String, Object> d, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified) {
        Map<String, Object> eff = ActionEffective.effective(d, reg, attestationVerified);
        Map<String, Object> card = ActionDerive.cardOf(d, eff, reg);
        Map<String, Object> e = J.m(eff.get("eff"));
        boolean confirmed = Boolean.TRUE.equals(eff.get("confirmed"));
        String rev = (String) e.get("rev");
        List<String> lines = new ArrayList<>();
        lines.add((String) card.get("text"));
        lines.add("effective: risk " + J.num(e.get("risk")).longValue() + ", " + (rev.equals("irreversible") ? "irreversible" : rev.equals("rate_limited") ? "rate limited" : "reversible")
            + ", blast " + blastText(J.num(e.get("blast_ppm")).longValue()) + ", escalation: " + card.get("escalation"));
        List<Object> needs = J.a(card.get("needs"));
        lines.add("grant must carry: " + (!needs.isEmpty() ? join(needs) : "nothing"));
        List<Object> ctx = J.a(card.get("context"));
        if (!ctx.isEmpty()) lines.add("call must carry: " + join(ctx));
        String closure = join(eff.get("closure"));
        String state = (String) J.get(d.get("review"), "state");
        lines.add("traits: " + (closure.isEmpty() ? "none" : closure));
        lines.add("review: " + (confirmed ? state : state + ", not confirmed by a signed review"));
        if (!confirmed) {
            Map<String, Object> h = J.m(eff.get("hint"));
            String hc = join(h.get("closure"));
            Map<String, Object> he = J.m(h.get("eff"));
            lines.add("until a reviewer signs it this action is treated as the most dangerous kind of action; as written it would be: risk " + J.num(he.get("risk")).longValue()
                + ", escalation tier " + J.num(he.get("esc")).longValue() + ", traits: " + (hc.isEmpty() ? "none" : hc));
        }
        return String.join("\n", lines);
    }
}
