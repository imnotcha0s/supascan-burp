package com.supascan.model;

import java.util.ArrayList;
import java.util.List;

/** Enumeration result for a storage bucket. */
public class BucketState {
    public String name;
    public int fileCount;
    public List<StorageObject> files = new ArrayList<>();

    public BucketState() {
    }

    public BucketState(String name) {
        this.name = name;
    }
}
