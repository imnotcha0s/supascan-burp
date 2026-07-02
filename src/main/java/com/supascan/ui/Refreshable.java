package com.supascan.ui;

import com.supascan.model.SupabaseInstance;

/** A panel that re-renders for the currently-selected instance (called on the EDT). */
public interface Refreshable {
    void refresh(SupabaseInstance current);
}
