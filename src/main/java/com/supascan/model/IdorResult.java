package com.supascan.model;

import java.util.ArrayList;
import java.util.List;

/** Cross-user differential read result for one table. */
public class IdorResult {
    public List<PerUser> perUser = new ArrayList<>();
    /** true = two distinct identities saw identical rows (same count + first id). */
    public boolean shared;
}
