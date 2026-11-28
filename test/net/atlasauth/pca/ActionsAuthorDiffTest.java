package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionAuthor;
import org.junit.jupiter.api.Test;

class ActionsAuthorDiffTest {
    private static final String M = "ref-actions-author";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    private static Long lng(Object o) { return o == null ? null : Long.valueOf(((Json.Num) o).raw); }
    private static List<String> strs(Object o) { List<String> out = new ArrayList<>(); for (Object x : (List<?>) o) out.add((String) x); return out; }

    @Test void paramShorthand() throws Exception { OracleCases.each(M, "parseParamShorthand", a -> ActionAuthor.parseParamShorthand((String) a.get(0))); }
    @Test void resourceShorthand() throws Exception { OracleCases.each(M, "parseResourceShorthand", a -> ActionAuthor.parseResourceShorthand((String) a.get(0))); }
    @Test void defaultTitle() throws Exception { OracleCases.each(M, "defaultTitle", a -> ActionAuthor.defaultTitle((String) a.get(0))); }
    @Test void expand() throws Exception { OracleCases.each(M, "expandAction", a -> ActionAuthor.expandAction(a.get(0), (String) a.get(1))); }
    @Test void load() throws Exception { OracleCases.each(M, "loadActionsValue", a -> ActionAuthor.loadActionsValue(a.get(0))); }
    @Test void action() throws Exception { OracleCases.each(M, "action", a -> ActionAuthor.action((String) a.get(0), m(a.get(1)))); }

    @Test void builder() throws Exception {
        OracleCases.each(M, "builder", a -> {
            Map<String, Object> x;
            switch ((String) a.get(0)) {
                case "email": return ActionAuthor.P.email(xs(a, 1));
                case "phone": return ActionAuthor.P.phone(xs(a, 1));
                case "url": return ActionAuthor.P.url(xs(a, 1));
                case "uuid": return ActionAuthor.P.uuid(xs(a, 1));
                case "ccy": return ActionAuthor.P.ccy(xs(a, 1));
                case "country": return ActionAuthor.P.country(xs(a, 1));
                case "secret": return ActionAuthor.P.secret(xs(a, 1));
                case "bool": return ActionAuthor.P.bool(xs(a, 1));
                case "date": return ActionAuthor.P.date(xs(a, 1));
                case "datetime": return ActionAuthor.P.datetime(xs(a, 1));
                case "duration": return ActionAuthor.P.duration(lng(a.get(1)), xs(a, 2));
                case "message": return ActionAuthor.P.message(lng(a.get(1)), xs(a, 2));
                case "text": return ActionAuthor.P.text(lng(a.get(1)), xs(a, 2));
                case "int": return ActionAuthor.P.intRange(lng(a.get(1)), lng(a.get(2)), xs(a, 3));
                case "count": return ActionAuthor.P.count(lng(a.get(1)), xs(a, 2));
                case "money": return ActionAuthor.P.money(a.get(1), a.get(2) == null ? null : m(a.get(2)), xs(a, 3));
                case "id": return ActionAuthor.P.id((String) a.get(1), xs(a, 2));
                case "enum": return ActionAuthor.P.enumOf(strs(a.get(1)), xs(a, 2));
                case "set": return ActionAuthor.P.setOf(strs(a.get(1)), xs(a, 2));
                case "array": return ActionAuthor.P.array((String) a.get(1), lng(a.get(2)), xs(a, 3));
                case "optional": x = m(a.get(1)); return ActionAuthor.P.optional(x);
                default: throw new IllegalArgumentException("unknown builder " + a.get(0));
            }
        });
    }

    private static Map<String, Object> xs(List<?> a, int i) { return i < a.size() && a.get(i) != null ? m(a.get(i)) : null; }
}
