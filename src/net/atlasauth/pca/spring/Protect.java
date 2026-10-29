package net.atlasauth.pca.spring;

import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import net.atlasauth.pca.ArgProvenance;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.MemoryStateStore;
import net.atlasauth.pca.PcaJdbcStateStore;
import net.atlasauth.pca.StateStore;
import net.atlasauth.pca.servlet.GrantResolver;
import net.atlasauth.pca.servlet.PcaFilter;

/**
 * {@code Protect.protect(...)}: the secure defaults for a resource server, in one call.
 *
 * <pre>{@code
 * Protect.Protected p = Protect.protect(new Protect.Config("payments-rs", (request, body) -> operationFor(request, body)).grants(grants));
 * registry.addInterceptor(p.interceptor());   // or register p.filter() as a servlet filter
 * p.revoke(grantId);                           // later: every action under that grant is refused
 * }</pre>
 *
 * It fills in the parts every server otherwise wires by hand, and nothing else: the grant lookup (your own list or function,
 * never the request), a replay store ({@link MemoryStateStore} unless you pass one), a revocation source, and the single-step
 * plan (the grant alone limits what runs). Everything is still {@link Authorize#authorize}: bound to the operation your route
 * executes, default-deny. Anything you set on {@link Config} wins over the default.
 *
 * <p>Not included (documented omission): this SDK has no connector-catalog risk pricing, so server-side risk inputs are not
 * derived; a grant whose policy needs them refuses with {@code risk_inputs}.
 */
public final class Protect {
    private Protect() {}

    /** What {@link #protect} needs: the audience, the operation your route executes, and the grants you accept. */
    public static final class Config {
        final String audience;
        final PcaFilter.OperationMapper operation;
        GrantResolver resolver;
        StateStore stateStore;
        Authorize.RevocationCheck isRevoked;
        Clock clock = Clock.systemUTC();
        String plan = Authorize.SINGLE_STEP;
        ArgProvenance.Options provenance;

        /** @param operation derives the operation from YOUR routing and parsed input (return null to deny) */
        public Config(String audience, PcaFilter.OperationMapper operation) {
            this.audience = Objects.requireNonNull(audience, "audience");
            this.operation = Objects.requireNonNull(operation, "operation");
        }

        /** The grants this server accepts, looked up by {@code id}. */
        public Config grants(List<Map<String, Object>> grants) {
            Map<String, Map<String, Object>> byId = new HashMap<>();
            for (Map<String, Object> g : grants) byId.put(String.valueOf(g.get("id")), g);
            this.resolver = byId::get;
            return this;
        }

        /** The grant lookup as a function from {@code grant_ref} to a grant (null: unknown). */
        public Config grants(GrantResolver resolver) { this.resolver = Objects.requireNonNull(resolver, "resolver"); return this; }

        /** Replay store; use {@link PcaJdbcStateStore} when several workers serve the route. Default: in memory. */
        public Config stateStore(StateStore stateStore) { this.stateStore = stateStore; return this; }

        /** Extra revocation source, consulted in addition to {@code revoke()}. */
        public Config isRevoked(Authorize.RevocationCheck isRevoked) { this.isRevoked = isRevoked; return this; }

        public Config clock(Clock clock) { this.clock = Objects.requireNonNull(clock, "clock"); return this; }

        /**
         * The provenance gate's configuration (pinned mediators, action facts; see {@link ArgProvenance}). The gate runs without it
         * too: then only a mediator the grant envelope names can vouch for a request, and a sensitive action escalates otherwise.
         */
        public Config provenance(ArgProvenance.Options provenance) { this.provenance = provenance; return this; }

        /** Plan mode; default {@link Authorize#SINGLE_STEP}. */
        public Config plan(String plan) { this.plan = Objects.requireNonNull(plan, "plan"); return this; }
    }

    /** The guard configuration plus the revoke handle. */
    public static final class Protected {
        private final Config c;
        private final Authorize.Options options;
        private final Set<String> revoked;

        Protected(Config c, Authorize.Options options, Set<String> revoked) { this.c = c; this.options = options; this.revoked = revoked; }

        /** The options to hand to a {@link PcaFilter} or {@link PcaInterceptor} you build yourself. */
        public Authorize.Options options() { return options; }

        /** A servlet filter enforcing the guard. */
        public PcaFilter filter() { return new PcaFilter(c.audience, c.resolver, c.clock, options, c.operation); }

        /** A Spring MVC interceptor enforcing the guard (its operation mapper gets an empty body). */
        public PcaInterceptor interceptor() { return new PcaInterceptor(c.audience, c.resolver, c.clock, options, c.operation); }

        /** Refuse every further action under this grant id. */
        public void revoke(String grantId) { revoked.add(grantId); }
    }

    /** Build the guard. Throws {@link IllegalArgumentException} when no grants were given: that would refuse everything. */
    public static Protected protect(Config c) {
        if (c.resolver == null) throw new IllegalArgumentException("protect: give grants(...) (a list or a lookup function)");
        Set<String> revoked = ConcurrentHashMap.newKeySet();
        Authorize.RevocationCheck extra = c.isRevoked;
        // your own source can only add refusals; a null answer from it stays null (undecided refuses)
        Authorize.RevocationCheck check = (pcactn, grant) -> {
            Object id = grant == null ? null : grant.get("id");
            if (id == null || revoked.contains(String.valueOf(id))) return Boolean.TRUE;
            return extra == null ? Boolean.FALSE : extra.isRevoked(pcactn, grant);
        };
        StateStore store = c.stateStore != null ? c.stateStore : new MemoryStateStore();
        Authorize.Options options = new Authorize.Options(store, check, c.plan, null, List.of());
        return new Protected(c, c.provenance != null ? options.withProvenance(c.provenance) : options, revoked);
    }
}
