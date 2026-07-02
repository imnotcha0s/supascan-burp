package com.supascan.ui;

import com.supascan.AppContext;
import com.supascan.model.ActivityEntry;
import com.supascan.model.SupabaseInstance;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.List;

/** Timestamped audit log of every active request the extension sends (spec §7.8). */
public final class ActivityPanel extends JPanel implements Refreshable {

    private final AppContext ctx;
    private final SupaScanTab host;
    private final DefaultTableModel model =
            UiUtil.readOnlyModel("Time", "Method", "URL", "Status", "Note");
    private final JTable table = UiUtil.readOnlyTable(model);

    public ActivityPanel(AppContext ctx, SupaScanTab host) {
        super(new BorderLayout(6, 6));
        this.ctx = ctx;
        this.host = host;

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        toolbar.add(UiUtil.button("Clear", e -> {
            ctx.registry.clearActivity();
            host.refreshAll();
        }));

        add(toolbar, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
    }

    @Override
    public void refresh(SupabaseInstance current) {
        model.setRowCount(0);
        List<ActivityEntry> entries = ctx.registry.activity();
        for (int i = entries.size() - 1; i >= 0; i--) { // newest first
            ActivityEntry a = entries.get(i);
            model.addRow(new Object[] {
                    a.timestamp, UiUtil.nz(a.method), UiUtil.nz(a.url),
                    a.statusCode == null ? "" : a.statusCode, UiUtil.nz(a.note)});
        }
    }
}
