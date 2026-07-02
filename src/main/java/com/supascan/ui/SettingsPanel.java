package com.supascan.ui;

import com.supascan.AppContext;
import com.supascan.model.PluginSettings;
import com.supascan.model.SupabaseInstance;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.file.Files;

/** Global settings (spec §8, §4). Persisted via Burp preferences. */
public final class SettingsPanel extends JPanel implements Refreshable {

    private final AppContext ctx;
    private final SupaScanTab host;

    private final JSpinner rps = new JSpinner(new SpinnerNumberModel(5, 1, 100, 1));
    private final JSpinner concurrency = new JSpinner(new SpinnerNumberModel(3, 1, 20, 1));
    private final JTextField testEmail = new JTextField(28);
    private final JCheckBox discovery = new JCheckBox("Enable discovery (brute-force wordlists)");
    private final JCheckBox useCustom = new JCheckBox("Use custom wordlist (else built-in defaults)");
    private final JTextArea wordlist = new JTextArea(8, 40);

    public SettingsPanel(AppContext ctx, SupaScanTab host) {
        super(new BorderLayout(6, 6));
        this.ctx = ctx;
        this.host = host;

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 3, 3, 3);
        g.anchor = GridBagConstraints.WEST;
        int y = 0;

        addRow(form, g, y++, new JLabel("Max requests / second:"), rps);
        addRow(form, g, y++, new JLabel("Max concurrency:"), concurrency);
        addRow(form, g, y++, new JLabel("Test email ({rand} supported):"), testEmail);
        addRow(form, g, y++, new JLabel("Discovery:"), discovery);
        addRow(form, g, y++, new JLabel("Wordlist source:"), useCustom);

        g.gridx = 0; g.gridy = y++; g.anchor = GridBagConstraints.NORTHWEST;
        form.add(new JLabel("Custom wordlist:"), g);
        g.gridx = 1; form.add(new JScrollPane(wordlist), g);

        g.gridx = 1; g.gridy = y;
        JPanel buttons = new JPanel();
        buttons.add(UiUtil.button("Load from file…", e -> loadFromFile()));
        buttons.add(UiUtil.button("Save settings", e -> save()));
        form.add(buttons, g);

        add(form, BorderLayout.NORTH);
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        loadFromSettings();
    }

    private void addRow(JPanel form, GridBagConstraints g, int y, JLabel label, java.awt.Component field) {
        g.gridx = 0; g.gridy = y; form.add(label, g);
        g.gridx = 1; form.add(field, g);
    }

    private void loadFromSettings() {
        PluginSettings s = ctx.registry.settings();
        rps.setValue(s.maxRequestsPerSecond);
        concurrency.setValue(s.maxConcurrency);
        testEmail.setText(s.testEmail);
        discovery.setSelected(s.discoveryEnabled);
        useCustom.setSelected(s.useCustomWordlist);
        wordlist.setText(s.tableWordlist);
    }

    private void loadFromFile() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                wordlist.setText(Files.readString(chooser.getSelectedFile().toPath()));
                useCustom.setSelected(true);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Read failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void save() {
        PluginSettings s = ctx.registry.settings();

        s.maxRequestsPerSecond = (Integer) rps.getValue();
        s.maxConcurrency = (Integer) concurrency.getValue();
        s.testEmail = testEmail.getText().trim();
        s.discoveryEnabled = discovery.isSelected();
        s.useCustomWordlist = useCustom.isSelected();
        s.tableWordlist = wordlist.getText();

        ctx.registry.saveSettings(s);
        ctx.applyLimits();
        host.refreshAll();
        host.status("Settings saved.");
    }

    @Override
    public void refresh(SupabaseInstance current) {
        // Reflect the discovery toggle if changed from the top bar.
        discovery.setSelected(ctx.registry.settings().discoveryEnabled);
    }
}
