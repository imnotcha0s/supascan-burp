package com.supascan.registry;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Preferences;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.supascan.model.ActivityEntry;
import com.supascan.model.PluginSettings;
import com.supascan.model.SupabaseInstance;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Per-project instance store + activity log + settings + issue-dedupe set.
 * An in-memory cache fronts Burp persistence; every mutation writes through.
 * Instances live in the project-scoped {@link PersistedObject}; settings are
 * global {@link Preferences} (spec §4).
 */
public final class Registry {

    private static final String K_INSTANCES = "supascan.instances";
    private static final String K_ACTIVITY = "supascan.activity";
    private static final String K_ISSUES = "supascan.issues";
    private static final String K_SETTINGS = "supascan.settings";
    private static final int ACTIVITY_CAP = 2000;

    private final MontoyaApi api;
    private final Gson gson = new Gson();

    private final Map<String, SupabaseInstance> instances = new LinkedHashMap<>();
    private final List<ActivityEntry> activity = new ArrayList<>();
    private final Set<String> raisedIssueKeys = new LinkedHashSet<>();
    private PluginSettings settings = new PluginSettings();

    private final CopyOnWriteArrayList<Runnable> listeners = new CopyOnWriteArrayList<>();

    public Registry(MontoyaApi api) {
        this.api = api;
        load();
    }

    // ------------------------------------------------------------- loading ---

    private synchronized void load() {
        PersistedObject data = api.persistence().extensionData();
        Preferences prefs = api.persistence().preferences();
        try {
            String iJson = data.getString(K_INSTANCES);
            if (iJson != null && !iJson.isBlank()) {
                Map<String, SupabaseInstance> m = gson.fromJson(
                        iJson, new TypeToken<LinkedHashMap<String, SupabaseInstance>>() { }.getType());
                if (m != null) {
                    instances.putAll(m);
                }
            }
            String aJson = data.getString(K_ACTIVITY);
            if (aJson != null && !aJson.isBlank()) {
                List<ActivityEntry> a = gson.fromJson(
                        aJson, new TypeToken<ArrayList<ActivityEntry>>() { }.getType());
                if (a != null) {
                    activity.addAll(a);
                }
            }
            String isJson = data.getString(K_ISSUES);
            if (isJson != null && !isJson.isBlank()) {
                Set<String> s = gson.fromJson(
                        isJson, new TypeToken<LinkedHashSet<String>>() { }.getType());
                if (s != null) {
                    raisedIssueKeys.addAll(s);
                }
            }
            String sJson = prefs.getString(K_SETTINGS);
            if (sJson != null && !sJson.isBlank()) {
                PluginSettings s = gson.fromJson(sJson, PluginSettings.class);
                if (s != null) {
                    settings = s.sanitized();
                }
            }
        } catch (RuntimeException e) {
            api.logging().logToError("SupaScan: failed to load persisted state: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------- instances ---

    public synchronized SupabaseInstance getOrCreate(String projectRef, String projectUrl) {
        SupabaseInstance inst = instances.get(projectRef);
        if (inst == null) {
            inst = new SupabaseInstance(projectRef, projectUrl);
            instances.put(projectRef, inst);
            persistInstances();
        } else if (inst.projectUrl == null && projectUrl != null) {
            inst.projectUrl = projectUrl;
            persistInstances();
        }
        return inst;
    }

    public synchronized SupabaseInstance get(String projectRef) {
        return instances.get(projectRef);
    }

    /** Snapshot copy for read-only UI iteration. */
    public synchronized List<SupabaseInstance> instances() {
        return new ArrayList<>(instances.values());
    }

    public synchronized boolean isEmpty() {
        return instances.isEmpty();
    }

    /** Ensure the instance is stored, then write through. */
    public synchronized void save(SupabaseInstance inst) {
        if (inst != null && inst.projectRef != null) {
            instances.put(inst.projectRef, inst);
            persistInstances();
        }
    }

    public synchronized void removeInstance(String projectRef) {
        if (instances.remove(projectRef) != null) {
            persistInstances();
        }
    }

    private void persistInstances() {
        try {
            api.persistence().extensionData().setString(K_INSTANCES, gson.toJson(instances));
        } catch (RuntimeException e) {
            api.logging().logToError("SupaScan: persist instances failed: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------ activity ---

    public ActivityEntry logActivity(String method, String url, Integer statusCode, String note) {
        ActivityEntry entry = new ActivityEntry(newId(), now(), method, url, statusCode, note);
        synchronized (this) {
            activity.add(entry);
            while (activity.size() > ACTIVITY_CAP) {
                activity.remove(0);
            }
            persistActivity();
        }
        fireChanged();
        return entry;
    }

    public synchronized List<ActivityEntry> activity() {
        return new ArrayList<>(activity);
    }

    public void clearActivity() {
        synchronized (this) {
            activity.clear();
            persistActivity();
        }
        fireChanged();
    }

    private void persistActivity() {
        try {
            api.persistence().extensionData().setString(K_ACTIVITY, gson.toJson(activity));
        } catch (RuntimeException e) {
            api.logging().logToError("SupaScan: persist activity failed: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------ settings ---

    public synchronized PluginSettings settings() {
        return settings;
    }

    public void saveSettings(PluginSettings s) {
        synchronized (this) {
            settings = s.sanitized();
            try {
                api.persistence().preferences().setString(K_SETTINGS, gson.toJson(settings));
            } catch (RuntimeException e) {
                api.logging().logToError("SupaScan: persist settings failed: " + e.getMessage());
            }
        }
        fireChanged();
    }

    // -------------------------------------------------------- issue dedupe ---

    public synchronized boolean isIssueRaised(String key) {
        return raisedIssueKeys.contains(key);
    }

    public synchronized void markIssueRaised(String key) {
        if (raisedIssueKeys.add(key)) {
            try {
                api.persistence().extensionData().setString(K_ISSUES, gson.toJson(raisedIssueKeys));
            } catch (RuntimeException e) {
                api.logging().logToError("SupaScan: persist issue keys failed: " + e.getMessage());
            }
        }
    }

    // ------------------------------------------------------------ listeners --

    public void addChangeListener(Runnable r) {
        listeners.add(r);
    }

    /** Notify UI listeners that state changed. Listeners marshal to the EDT themselves. */
    public void fireChanged() {
        for (Runnable r : listeners) {
            try {
                r.run();
            } catch (RuntimeException e) {
                api.logging().logToError("SupaScan: listener error: " + e.getMessage());
            }
        }
    }

    // --------------------------------------------------------------- utils ---

    public static String now() {
        return Instant.now().toString();
    }

    public static String newId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
