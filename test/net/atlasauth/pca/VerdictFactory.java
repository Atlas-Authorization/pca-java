package net.atlasauth.pca;

/** Test-only access to the package-private Verdict constructor / fail(). */
public final class VerdictFactory {
    private VerdictFactory() {}
    public static Pca.Verdict empty() { return new Pca.Verdict(); }
    public static Pca.Verdict failed(String name, String why) { Pca.Verdict v = new Pca.Verdict(); v.fail(name, why); return v; }
}
