package net.atlasauth.pca.connectors;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.connectors.ConnectorError.UnknownProviderError;

/**
 * The connector registry: an in-memory map of provider id to {@link ProviderManifest}. A manifest is validated on the way in, so nothing
 * malformed can ever be looked up. {@link #defaultRegistry()} is the process-wide registry seeded with the built-in catalog; callers who want
 * isolation build their own with {@link #createDefaultRegistry()}.
 */
public final class ProviderRegistry {
    private final Map<String, ProviderManifest> byId = new HashMap<>();

    /** Options of {@link #register}: replace on purpose, and/or pin the digest of the manifest you reviewed. */
    public static final class RegisterOptions {
        public boolean replace;
        /** Null = no pin. */
        public String expectedDigest;
        public RegisterOptions() {}
        public RegisterOptions(boolean replace, String expectedDigest) { this.replace = replace; this.expectedDigest = expectedDigest; }
    }

    /**
     * Validate and register a manifest (a {@link ProviderManifest} or an untrusted parsed-JSON tree). Throws {@code ManifestValidationError} on a
     * malformed input, and refuses to replace a provider that is already registered: silently swapping the manifest of {@code google} would send its
     * tokens to a different endpoint.
     */
    public synchronized ProviderManifest register(Object manifest, RegisterOptions opts) {
        ProviderManifest valid = Manifest.assertManifest(manifest instanceof ProviderManifest ? ((ProviderManifest) manifest).toMap() : manifest);
        if (opts != null && opts.expectedDigest != null && !Manifest.manifestDigest(valid).equals(opts.expectedDigest)) {
            throw new ConnectorError("manifest '" + valid.id + "' does not match the pinned digest");
        }
        if (byId.containsKey(valid.id) && !(opts != null && opts.replace)) {
            throw new ConnectorError("provider '" + valid.id + "' is already registered; pass { replace: true } to replace it deliberately");
        }
        byId.put(valid.id, valid);
        return valid;
    }

    public ProviderManifest register(Object manifest) { return register(manifest, null); }

    /** The manifest for {@code id}, or null when none is registered. */
    public synchronized ProviderManifest get(String id) { return byId.get(id); }

    /** The manifest for {@code id}, or throw {@link UnknownProviderError}. */
    public synchronized ProviderManifest require(String id) {
        ProviderManifest m = byId.get(id);
        if (m == null) throw new UnknownProviderError(id);
        return m;
    }

    public synchronized boolean has(String id) { return byId.containsKey(id); }

    /** Every registered manifest, in ascending id order. */
    public synchronized List<ProviderManifest> list() {
        List<ProviderManifest> out = new ArrayList<>(byId.values());
        out.sort((a, b) -> a.id.compareTo(b.id));
        return out;
    }

    /** The registered provider ids, in ascending order. */
    public List<String> ids() {
        List<String> out = new ArrayList<>();
        for (ProviderManifest m : list()) out.add(m.id);
        return out;
    }

    /** A fresh registry seeded with the full built-in connector catalog. */
    public static ProviderRegistry createDefaultRegistry() {
        ProviderRegistry r = new ProviderRegistry();
        for (ProviderManifest m : Providers.BUILTIN_MANIFESTS) r.register(m);
        return r;
    }

    private static final class Holder {
        static final ProviderRegistry DEFAULT = createDefaultRegistry();
    }

    /** The process-wide registry the top-level {@link #registerProvider} / {@link #getProvider} / {@link #listProviders} operate on. */
    public static ProviderRegistry defaultRegistry() { return Holder.DEFAULT; }

    /** Validate and register a custom manifest onto the default registry. */
    public static ProviderManifest registerProvider(Object manifest, RegisterOptions opts) { return defaultRegistry().register(manifest, opts); }

    /** A digest of the whole registry (every manifest, by id). Pin it to detect any change to the catalog. */
    public static String catalogDigest(ProviderRegistry registry) {
        List<Object> rows = new ArrayList<>();
        for (ProviderManifest m : registry.list()) rows.add(new ArrayList<Object>(List.of(m.id, Manifest.manifestDigest(m))));
        return Pca.hashCanonical(rows);
    }

    public static String catalogDigest() { return catalogDigest(defaultRegistry()); }

    /** The manifest for {@code id} in the default registry, or null. */
    public static ProviderManifest getProvider(String id) { return defaultRegistry().get(id); }

    /** Every manifest in the default registry, in ascending id order. */
    public static List<ProviderManifest> listProviders() { return Collections.unmodifiableList(defaultRegistry().list()); }
}
