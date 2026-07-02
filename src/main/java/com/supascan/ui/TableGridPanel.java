package com.supascan.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.supascan.AppContext;
import com.supascan.extract.Extract;
import com.supascan.model.IdorResult;
import com.supascan.model.PerUser;
import com.supascan.model.SupabaseInstance;
import com.supascan.model.TableState;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.List;
import java.util.Map;

/** Tables grid + master-detail sample row, IDOR diff, and Send-to-Repeater. */
public final class TableGridPanel extends JPanel implements Refreshable {

    private final AppContext ctx;
    private final SupaScanTab host;

    private final DefaultTableModel model =
            UiUtil.readOnlyModel("Table", "Read", "Rows", "Write", "Columns");
    private final JTable table = UiUtil.readOnlyTable(model);
    private final JTextArea detail = new JTextArea(8, 60);

    public TableGridPanel(AppContext ctx, SupaScanTab host) {
        super(new BorderLayout(6, 6));
        this.ctx = ctx;
        this.host = host;
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showDetail();
            }
        });
        detail.setEditable(false);
        detail.setLineWrap(true);
        detail.setWrapStyleWord(true);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        toolbar.add(UiUtil.button("Clear tables", e -> clearTables()));
        toolbar.add(UiUtil.button("Copy sample", e -> {
            TableState ts = selected();
            if (ts != null && ts.sampleRow != null) {
                UiUtil.copy(ts.sampleRow);
                host.status("Sample row copied.");
            }
        }));
        toolbar.add(UiUtil.button("Send GET → Repeater", e -> sendGet()));
        toolbar.add(UiUtil.button("Send POST → Repeater", e -> sendPost()));
        toolbar.add(UiUtil.button("Send PATCH → Repeater", e -> sendPatch()));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), new JScrollPane(detail));
        split.setResizeWeight(0.6);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
    }

    private void clearTables() {
        SupabaseInstance inst = host.current();
        if (inst != null) {
            inst.tables.clear();
            ctx.registry.save(inst);
            host.refreshAll();
        }
    }

    private TableState selected() {
        SupabaseInstance inst = host.current();
        int row = table.getSelectedRow();
        if (inst == null || row < 0) {
            return null;
        }
        return inst.tables.get((String) model.getValueAt(row, 0));
    }

    private void showDetail() {
        TableState ts = selected();
        if (ts == null) {
            detail.setText("");
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Table: public.").append(ts.name).append('\n');
        sb.append("Read: ").append(UiUtil.nz(ts.anonRead))
                .append("   Rows: ").append(ts.rowCount == null ? "?" : ts.rowCount)
                .append("   Write: ").append(UiUtil.nz(ts.anonWrite)).append('\n');
        if (ts.columns != null) {
            sb.append("Columns: ").append(String.join(", ", ts.columns)).append('\n');
        }
        if (ts.sampleRow != null) {
            sb.append("\nSample row:\n").append(ts.sampleRow).append('\n');
        }
        if (ts.idor != null) {
            sb.append("\nIDOR / cross-user differential")
                    .append(ts.idor.shared ? " — SHARED (potential broken RLS):\n" : ":\n");
            for (PerUser pu : ts.idor.perUser) {
                sb.append("  ").append(pu.label).append(": count=")
                        .append(pu.rowCount == null ? "?" : pu.rowCount)
                        .append(", firstId=").append(UiUtil.nz(pu.sampleId)).append('\n');
            }
        }
        detail.setText(sb.toString());
        detail.setCaretPosition(0);
    }

    // ---- Send to Repeater ----

    private void sendGet() {
        SupabaseInstance inst = host.current();
        TableState ts = selected();
        if (inst == null || ts == null) {
            return;
        }
        String url = inst.projectUrl + "/rest/v1/" + ts.name + "?select=*&limit=1";
        HttpRequest req = ctx.http.build("GET", url, Extract.credsFor(inst), null, null);
        ctx.api.repeater().sendToRepeater(req, "SupaScan GET " + ts.name);
        host.status("Sent GET " + ts.name + " to Repeater.");
    }

    private void sendPost() {
        SupabaseInstance inst = host.current();
        TableState ts = selected();
        if (inst == null || ts == null) {
            return;
        }
        String url = inst.projectUrl + "/rest/v1/" + ts.name;
        String body = ts.sampleRow != null ? ts.sampleRow : "{}";
        HttpRequest req = ctx.http.build("POST", url, Extract.credsFor(inst),
                Map.of("Content-Type", "application/json", "Prefer", "return=representation"), body);
        ctx.api.repeater().sendToRepeater(req, "SupaScan POST " + ts.name);
        host.status("Sent POST " + ts.name + " to Repeater (operator-driven).");
    }

    private void sendPatch() {
        SupabaseInstance inst = host.current();
        TableState ts = selected();
        if (inst == null || ts == null) {
            return;
        }
        String filterCol = (ts.columns != null && ts.columns.contains("id")) ? "id"
                : (ts.columns != null && !ts.columns.isEmpty() ? ts.columns.get(0) : "id");
        String url = inst.projectUrl + "/rest/v1/" + ts.name
                + "?and=(" + filterCol + ".is.null," + filterCol + ".not.is.null)";
        String body = ts.sampleRow != null ? ts.sampleRow : "{\"_supascan_probe\":\"test\"}";
        HttpRequest req = ctx.http.build("PATCH", url, Extract.credsFor(inst),
                Map.of("Content-Type", "application/json", "Prefer", "tx=rollback,return=representation"), body);
        ctx.api.repeater().sendToRepeater(req, "SupaScan PATCH " + ts.name);
        host.status("Sent PATCH " + ts.name + " to Repeater (tx=rollback).");
    }

    @Override
    public void refresh(SupabaseInstance current) {
        model.setRowCount(0);
        if (current == null) {
            return;
        }
        for (Map.Entry<String, TableState> e : current.tables.entrySet()) {
            TableState ts = e.getValue();
            List<String> cols = ts.columns;
            model.addRow(new Object[] {
                    ts.name,
                    UiUtil.nz(ts.anonRead),
                    ts.rowCount == null ? "" : ts.rowCount,
                    UiUtil.nz(ts.anonWrite),
                    cols == null ? "" : String.valueOf(cols.size())});
        }
        showDetail();
    }
}
