package com.supascan.model;

/** A single object found inside a storage bucket. */
public class StorageObject {
    public String path;
    public Long size;
    public String mimetype;

    public StorageObject() {
    }

    public StorageObject(String path, Long size, String mimetype) {
        this.path = path;
        this.size = size;
        this.mimetype = mimetype;
    }
}
