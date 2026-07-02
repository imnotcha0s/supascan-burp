package com.supascan.model;

import java.util.List;

/** Per-table probe state. */
public class TableState {
    public String name;
    public boolean observed;

    /** "rows" | "empty" | "denied" | "untested" */
    public String anonRead = "untested";
    public Integer rowCount;

    /** "accepted" | "rejected" | "untested" */
    public String anonWrite = "untested";

    public List<String> columns;
    /** JSON of the single sampled row (limit=1), stored raw. */
    public String sampleRow;

    public IdorResult idor;
}
