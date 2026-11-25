package net.atlasauth.pca.wallet;

import java.util.List;
import java.util.Map;

/** The wallet's view of the effective grant (the learner's acceptance and the ceilings), consulted by the question channel. */
public interface WalletView {
    /** p_k(c): the probability the principal's intent admits the cell. */
    double p(String verb, int[] idx);

    boolean vetoed(String verb, int[] idx);

    /** Outside every ceiling the principal cannot widen: never a question. */
    boolean outsideCeiling(String verb, int[] idx);

    /** Cells currently in the effective grant (for near-boundary canaries): maps {verb, idx}. */
    List<Map<String, Object>> confirmed();
}
