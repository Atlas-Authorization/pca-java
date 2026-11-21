package net.atlasauth.pca.boot;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** {@code pca.*} application properties. Nothing is enforced until {@code pca.audience} is set. */
@ConfigurationProperties(prefix = "pca")
public class PcaProperties {
    public enum Store { MEMORY, JDBC }

    public enum Mode { INTERCEPTOR, SECURITY }

    /** Master switch (default on); the guard still needs {@code pca.audience}. */
    private boolean enabled = true;
    /** This resource server's audience. A PCActn minted for another audience is refused. */
    private String audience;
    /** Replay store: {@code memory} (one JVM) or {@code jdbc} (the application's {@code DataSource}). */
    private Store store = Store.MEMORY;
    /** {@code interceptor}: a Spring MVC interceptor; {@code security}: expose a {@code PcaSecurity} for {@code http.with(...)} (needs pca-spring-security). */
    private Mode mode = Mode.INTERCEPTOR;
    /** Where the accepted grants are loaded from (a JSON array), e.g. {@code classpath:pca/grants.json}. Not needed when you define a {@code GrantResolver} bean. */
    private String grantsLocation;
    /** Paths the interceptor guards. Default: everything. */
    private List<String> pathPatterns = new ArrayList<>(List.of("/**"));
    /** Paths excluded from the interceptor. */
    private List<String> excludePathPatterns = new ArrayList<>();
    private final Jdbc jdbc = new Jdbc();

    public static class Jdbc {
        /** Replay table name. */
        private String table = "pca_replay";
        /** Create the replay table on startup (idempotent). */
        private boolean createTable = false;

        public String getTable() { return table; }
        public void setTable(String table) { this.table = table; }
        public boolean isCreateTable() { return createTable; }
        public void setCreateTable(boolean createTable) { this.createTable = createTable; }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getAudience() { return audience; }
    public void setAudience(String audience) { this.audience = audience; }
    public Store getStore() { return store; }
    public void setStore(Store store) { this.store = store; }
    public Mode getMode() { return mode; }
    public void setMode(Mode mode) { this.mode = mode; }
    public String getGrantsLocation() { return grantsLocation; }
    public void setGrantsLocation(String grantsLocation) { this.grantsLocation = grantsLocation; }
    public List<String> getPathPatterns() { return pathPatterns; }
    public void setPathPatterns(List<String> pathPatterns) { this.pathPatterns = pathPatterns; }
    public List<String> getExcludePathPatterns() { return excludePathPatterns; }
    public void setExcludePathPatterns(List<String> excludePathPatterns) { this.excludePathPatterns = excludePathPatterns; }
    public Jdbc getJdbc() { return jdbc; }
}
