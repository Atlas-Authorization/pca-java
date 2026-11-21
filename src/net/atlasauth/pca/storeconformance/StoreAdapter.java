package net.atlasauth.pca.storeconformance;

/**
 * The adapter a store author implements to run the conformance kit against THEIR store: {@link #open()} returns one client per
 * simulated verifier instance, all on the same shared backend.
 */
public interface StoreAdapter {
    /** Shown in reports. */
    String name();

    default Capabilities capabilities() { return null; }

    /** Open one client against the shared backend. Called once per simulated verifier instance. */
    StoreClient open() throws Exception;

    /** Optional: whether {@link #restart()} is implemented. */
    default boolean hasRestart() { return false; }

    /** Restart the BACKEND after every client was closed. Without it the durability test only closes and re-opens clients. */
    default void restart() throws Exception {}

    /** Optional: whether {@link #crash()} is implemented. */
    default boolean hasCrash() { return false; }

    /** Crash the backend abruptly (kill -9 equivalent). Followed by {@link #restart()}. Used by the crash test. */
    default void crash() throws Exception {}

    /** Release everything the adapter holds (pools, temp dirs). Never drop shared data here. */
    default void teardown() throws Exception {}

    /** What the adapter declares; a null member is detected from the first client (or, for {@code durable}, assumed true). */
    final class Capabilities {
        public Boolean consumeOnce, advance;
        /**
         * The store claims durability: consumed keys and counters survive closing every client and {@code restart()}. Declare false ONLY
         * for a single-process in-memory store whose lifetime covers the action lifetime; the durability test is then skipped.
         */
        public Boolean durable;

        public Capabilities durable(boolean d) { durable = d; return this; }
        public Capabilities consumeOnce(boolean d) { consumeOnce = d; return this; }
        public Capabilities advance(boolean d) { advance = d; return this; }
    }
}
