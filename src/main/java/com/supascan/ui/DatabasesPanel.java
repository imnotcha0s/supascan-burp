package com.supascan.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.supascan.AppContext;
import com.supascan.extract.Extract;
import com.supascan.model.SchemaState;
import com.supascan.model.SupabaseInstance;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.Map;

/** Schema / role privilege-escalation results + Accept-Profile→Repeater. */
public final class DatabasesPanel extends JPanel implements Refreshable {

    private final AppContext ctx;
    private final SupaScanTab host;

    private final JLabel testedAs = new JLabel("Tested as: —");
    private final DefaultTableModel model =
            UiUtil.readOnlyModel("Schema", "Sensitivity", "Reachable", "Status");
    private final JTable table = UiUtil.readOnlyTable(model);

    public DatabasesPanel(AppContext ctx, SupaScanTab host) {
        super(new BorderLayout(6, 6));
        this.ctx = ctx;
        this.host = host;
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(testedAs);

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bottom.add(UiUtil.button("Send Accept-Profile → Repeater", e -> sendToRepeater()));

        add(top, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
    }

    private void sendToRepeater() {
        SupabaseInstance inst = host.current();
        int row = table.getSelectedRow();
        if (inst == null || row < 0) {
            return;
        }
        String schema = (String) model.getValueAt(row, 0);
        HttpRequest req = ctx.http.build("GET", inst.projectUrl + "/rest/v1/", Extract.credsFor(inst),
                Map.of("Accept-Profile", schema), null);
        ctx.api.repeater().sendToRepeater(req, "SupaScan schema " + schema);
        host.status("Sent Accept-Profile: " + schema + " to Repeater.");
    }

    @Override
    public void refresh(SupabaseInstance current) {
        model.setRowCount(0);
        if (current == null) {
            testedAs.setText("Tested as: —");
            return;
        }
        testedAs.setText("Tested as: " + (current.activeSession() != null
                ? current.activeSession().label() : "anon"));
        for (Map.Entry<String, SchemaState> e : current.schemaStates.entrySet()) {
            SchemaState st = e.getValue();
            model.addRow(new Object[] {
                    st.name, UiUtil.nz(st.sensitivity),
                    st.exposed ? "REACHABLE" : "no",
                    st.status == null ? "" : st.status});
        }
    }
}
