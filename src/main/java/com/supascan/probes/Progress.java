package com.supascan.probes;

/** Progress sink for a running probe. Implementations marshal to the EDT. */
@FunctionalInterface
public interface Progress {
    void update(String message);

    Progress NOOP = m -> { };
}
