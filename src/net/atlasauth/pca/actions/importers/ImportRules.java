package net.atlasauth.pca.actions.importers;

import java.util.Map;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;

/** The shipped suggestion rules: DATA, versioned. Every rule only ADDS. These are heuristics measured against a labeled corpus; none is a safety guarantee. */
public final class ImportRules {
    private ImportRules() {}

    public static final String DEFAULT_RULES_VERSION = "1.1.0";

    @SuppressWarnings("unchecked")
    public static final Map<String, Object> DEFAULT_RULES = (Map<String, Object>) IntentJs.normalize(Json.parseLenient(ImportRulesData.json()));

    /** The default rule set with its digest. */
    public static final Map<String, Object> DEFAULT_RULES_SEALED = ImportSuggest.sealRules(DEFAULT_RULES);

    /** The digest recorded when the rule set was published. */
    public static String publishedDigest() { return ImportRulesData.SEALED_DIGEST; }
}
