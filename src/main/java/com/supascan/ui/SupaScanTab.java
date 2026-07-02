package com.supascan.ui;

import com.supascan.AppContext;
import com.supascan.extract.Extract;
import com.supascan.model.SessionUser;
import com.supascan.model.SupabaseInstance;
import com.supascan.probes.Progress;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * The "SupaScan" suite tab: top action strip + sub-tabs. Coordinates the
 * selected instance and its active identity, gates active checks on usable
 * credentials, and refreshes all panels on the EDT when the registry changes.
 */
public final class SupaScanTab {

    private final AppContext ctx;
    private final JPanel root = new JPanel(new BorderLayout());

    private final JComboBox<String> instanceCombo = new JComboBox<>();
    private final JComboBox<String> sessionCombo = new JComboBox<>();
    private final JLabel serviceRoleBanner = new JLabel();
    private final JLabel activeIdentity = new JLabel();
    private final JCheckBox discoveryToggle = new JCheckBox("Discovery");
    private final JLabel progress = new JLabel(" ");
    private final List<JButton> probeButtons = new ArrayList<>();
    private final List<Refreshable> panels = new ArrayList<>();

    private String selectedRef;
    private boolean updatingUi;

    public SupaScanTab(AppContext ctx) {
        this.ctx = ctx;
        build();
        ctx.registry.addChangeListener(() -> UiUtil.edt(this::refreshAll));
        refreshAll();
    }

    public Component component() {
        return root;
    }

    private void build() {
        JTabbedPane tabs = new JTabbedPane();
        addPanel(tabs, "Instances", new InstancesPanel(ctx, this));
        addPanel(tabs, "Tables", new TableGridPanel(ctx, this));
        addPanel(tabs, "Storage", new StoragePanel(ctx, this));
        addPanel(tabs, "RPC", new RpcPanel(ctx, this));
        addPanel(tabs, "Databases", new DatabasesPanel(ctx, this));
        addPanel(tabs, "Sessions", new SessionsPanel(ctx, this));
        addPanel(tabs, "Signup", new SignupPanel(ctx, this));
        addPanel(tabs, "Activity", new ActivityPanel(ctx, this));
        addPanel(tabs, "Settings", new SettingsPanel(ctx, this));

        root.add(buildTopStrip(), BorderLayout.NORTH);
        root.add(tabs, BorderLayout.CENTER);
    }

    private void addPanel(JTabbedPane tabs, String title, JComponent panel) {
        tabs.addTab(title, panel);
        if (panel instanceof Refreshable r) {
            panels.add(r);
        }
    }

    private JPanel buildTopStrip() {
        JPanel strip = new JPanel();
        strip.setLayout(new BoxLayout(strip, BoxLayout.Y_AXIS));
        strip.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row1.add(new JLabel("Instance:"));
        instanceCombo.addActionListener(e -> {
            if (updatingUi) {
                return;
            }
            Object sel = instanceCombo.getSelectedItem();
            if (sel != null) {
                selectedRef = (String) sel;
                refreshDynamic();
            }
        });
        row1.add(instanceCombo);
        row1.add(new JLabel("  Session:"));
        sessionCombo.addActionListener(e -> {
            if (updatingUi) {
                return;
            }
            onSessionSelected();
        });
        row1.add(sessionCombo);
        serviceRoleBanner.setForeground(Color.RED);
        row1.add(serviceRoleBanner);

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row2.add(activeIdentity);
        discoveryToggle.addActionListener(e -> {
            if (updatingUi) {
                return;
            }
            ctx.registry.settings().discoveryEnabled = discoveryToggle.isSelected();
            ctx.registry.saveSettings(ctx.registry.settings());
        });
        row2.add(discoveryToggle);

        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row3.add(probeButton("Read", p -> ctx.readProbe.run(current(), p)));
        row3.add(probeButton("Write", p -> ctx.writeProbe.run(current(), p)));
        row3.add(probeButton("Auth", p -> ctx.authProbe.runSignupCheck(current(), p)));
        row3.add(probeButton("RPC", p -> ctx.rpcProbe.run(current(), false, List.of(), p)));
        row3.add(probeButton("IDOR/RLS", p -> ctx.idorProbe.run(current(), p)));
        row3.add(probeButton("Databases", p -> ctx.rolesProbe.run(current(), p)));
        JButton stop = UiUtil.button("Stop all", e -> {
            ctx.stopAll();
            status("Stopped all checks.");
        });
        stop.setForeground(Color.RED);
        row3.add(Box.createHorizontalStrut(12));
        row3.add(stop);

        JPanel row4 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row4.add(new JLabel("Status:"));
        row4.add(progress);

        strip.add(row1);
        strip.add(row2);
        strip.add(row3);
        strip.add(row4);
        return strip;
    }

    private JButton probeButton(String label, Consumer<Progress> body) {
        JButton b = UiUtil.button(label, e -> runProbe(body));
        probeButtons.add(b);
        return b;
    }

    // ------------------------------------------------------- coordination ----

    public SupabaseInstance current() {
        return selectedRef == null ? null : ctx.registry.get(selectedRef);
    }

    public void selectInstance(String ref) {
        this.selectedRef = ref;
        refreshDynamic();
    }

    public void status(String message) {
        UiUtil.edt(() -> progress.setText(message));
    }

    /** Why active checks can't run for this instance right now, or null if they can. */
    private String gateReason(SupabaseInstance inst) {
        if (inst == null) {
            return "Select an instance first.";
        }
        if (!Extract.credsFor(inst).usable()) {
            return "No usable credentials — add an anon key or a session.";
        }
        return null;
    }

    public void runProbe(Consumer<Progress> body) {
        SupabaseInstance inst = current();
        String reason = gateReason(inst);
        if (reason != null) {
            status(reason);
            return;
        }
        ctx.armForRun();
        Progress p = msg -> UiUtil.edt(() -> progress.setText(msg));
        ctx.submit(() -> {
            try {
                body.accept(p);
            } catch (RuntimeException ex) {
                ctx.api.logging().logToError("SupaScan probe error: " + ex);
                p.update("Error: " + ex.getMessage());
            }
        });
    }

    public void refreshAll() {
        UiUtil.edt(() -> {
            rebuildInstanceCombo();
            refreshDynamic();
        });
    }

    /** Refresh top-strip state + panels for the current instance (combo unchanged). */
    private void refreshDynamic() {
        updatingUi = true;
        try {
            SupabaseInstance inst = current();

            rebuildSessionCombo(inst);

            serviceRoleBanner.setText(inst != null && inst.hasServiceRoleLeak()
                    ? "  ⚠ service_role key LEAKED — rotate immediately" : "");

            activeIdentity.setText("Checks run as: "
                    + (inst == null ? "—" : (inst.activeSession() != null
                    ? inst.activeSession().label() : "anon")));

            discoveryToggle.setSelected(ctx.registry.settings().discoveryEnabled);

            String gate = gateReason(inst);
            for (JButton b : probeButtons) {
                b.setEnabled(gate == null);
            }
            // Disabled buttons can't show a tooltip, so surface the blocking reason in
            // the status line — this replaces the scope badge as the "why can't I run" cue.
            if (gate != null) {
                progress.setText(gate);
            }

            for (Refreshable r : panels) {
                r.refresh(inst);
            }
        } finally {
            updatingUi = false;
        }
    }

    /** Apply the session-combo selection as the active identity for the current instance. */
    private void onSessionSelected() {
        SupabaseInstance inst = current();
        if (inst == null) {
            return;
        }
        int idx = sessionCombo.getSelectedIndex();
        String chosen = (idx <= 0 || idx - 1 >= inst.sessions.size())
                ? null // index 0 (or out of range) = anonymous
                : inst.sessions.get(idx - 1).id;
        if (Objects.equals(chosen, inst.activeSessionId)) {
            return; // programmatic reselect or no real change
        }
        inst.activeSessionId = chosen;
        ctx.registry.save(inst);
        refreshDynamic();
    }

    /** Rebuild the identity dropdown: index 0 = anon, then one row per session. */
    private void rebuildSessionCombo(SupabaseInstance inst) {
        sessionCombo.removeAllItems();
        if (inst == null) {
            sessionCombo.setEnabled(false);
            return;
        }
        sessionCombo.setEnabled(true);
        sessionCombo.addItem(inst.anonKey != null ? "anon" : "anon (no key)");
        for (SessionUser u : inst.sessions) {
            sessionCombo.addItem(u.label());
        }
        int sel = 0;
        if (inst.activeSessionId != null) {
            for (int i = 0; i < inst.sessions.size(); i++) {
                if (inst.activeSessionId.equals(inst.sessions.get(i).id)) {
                    sel = i + 1;
                    break;
                }
            }
        }
        sessionCombo.setSelectedIndex(sel);
    }

    private void rebuildInstanceCombo() {
        updatingUi = true;
        try {
            List<SupabaseInstance> all = ctx.registry.instances();
            if (selectedRef == null && !all.isEmpty()) {
                selectedRef = all.get(0).projectRef;
            }
            if (current() == null) {
                selectedRef = all.isEmpty() ? null : all.get(0).projectRef;
            }
            instanceCombo.removeAllItems();
            for (SupabaseInstance inst : all) {
                instanceCombo.addItem(inst.projectRef);
            }
            if (selectedRef != null) {
                instanceCombo.setSelectedItem(selectedRef);
            }
        } finally {
            updatingUi = false;
        }
    }
}
