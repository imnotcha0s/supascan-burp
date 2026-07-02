package com.supascan.ui;

import com.supascan.AppContext;
import com.supascan.model.SupabaseInstance;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.List;

/** Lists discovered instances; selecting one drives the rest of the UI. */
public final class InstancesPanel extends JPanel implements Refreshable {

    private final AppContext ctx;
    private final SupaScanTab host;
    private final DefaultTableModel model =
            UiUtil.readOnlyModel("Project ref", "URL", "In scope", "anon key", "service_role");
    private final JTable table = UiUtil.readOnlyTable(model);
    private boolean updating;

    public InstancesPanel(AppContext ctx, SupaScanTab host) {
        super(new BorderLayout(6, 6));
        this.ctx = ctx;
        this.host = host;

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (updating || e.getValueIsAdjusting()) {
                return;
            }
            int row = table.getSelectedRow();
            if (row >= 0) {
                host.selectInstance((String) model.getValueAt(row, 0));
            }
        });

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        toolbar.add(UiUtil.button("Refresh", e -> host.refreshAll()));
        toolbar.add(UiUtil.button("Remove", e -> removeSelected()));
        toolbar.add(UiUtil.button("Copy anon key", e -> copyAnon()));

        add(toolbar, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
    }

    private void removeSelected() {
        int row = table.getSelectedRow();
        if (row >= 0) {
            ctx.registry.removeInstance((String) model.getValueAt(row, 0));
            host.refreshAll();
        }
    }

    private void copyAnon() {
        SupabaseInstance c = host.current();
        if (c != null && c.anonKey != null) {
            UiUtil.copy(c.anonKey);
            host.status("anon key copied.");
        }
    }

    @Override
    public void refresh(SupabaseInstance current) {
        updating = true;
        try {
            model.setRowCount(0);
            List<SupabaseInstance> all = ctx.registry.instances();
            int selectRow = -1;
            for (int i = 0; i < all.size(); i++) {
                SupabaseInstance inst = all.get(i);
                model.addRow(new Object[] {
                        inst.projectRef,
                        inst.projectUrl,
                        ctx.scope.instanceInScope(inst) ? "yes" : "no",
                        inst.anonKey != null ? "yes (" + UiUtil.nz(inst.anonKeyRole) + ")" : "no",
                        inst.hasServiceRoleLeak() ? "LEAKED" : "—"
                });
                if (current != null && current.projectRef.equals(inst.projectRef)) {
                    selectRow = i;
                }
            }
            if (selectRow >= 0) {
                table.setRowSelectionInterval(selectRow, selectRow);
            }
        } finally {
            updating = false;
        }
    }
}
