package com.supascan.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.supascan.AppContext;
import com.supascan.extract.Extract;
import com.supascan.model.RpcState;
import com.supascan.model.SupabaseInstance;
import com.supascan.probes.Wordlists;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.Map;

/** RPC enumeration / brute-force UI + Call-in-Repeater. */
public final class RpcPanel extends JPanel implements Refreshable {

    private final AppContext ctx;
    private final SupaScanTab host;

    private final JTextField customNames = new JTextField(28);
    private final DefaultTableModel model =
            UiUtil.readOnlyModel("Function", "Status", "Reachable", "Elevated");
    private final JTable table = UiUtil.readOnlyTable(model);

    public RpcPanel(AppContext ctx, SupaScanTab host) {
        super(new BorderLayout(6, 6));
        this.ctx = ctx;
        this.host = host;
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Custom function names:"));
        top.add(customNames);
        top.add(UiUtil.button("Enumerate (OpenAPI)", e -> run(false)));
        top.add(UiUtil.button("Bruteforce", e -> run(true)));

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bottom.add(UiUtil.button("Call in Repeater", e -> callInRepeater()));

        add(top, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
    }

    private void run(boolean bruteforce) {
        SupabaseInstance inst = host.current();
        if (inst == null) {
            return;
        }
        var custom = Wordlists.parse(customNames.getText());
        host.runProbe(p -> ctx.rpcProbe.run(inst, bruteforce, custom, p));
    }

    private void callInRepeater() {
        SupabaseInstance inst = host.current();
        int row = table.getSelectedRow();
        if (inst == null || row < 0) {
            return;
        }
        String fn = (String) model.getValueAt(row, 0);
        String url = inst.projectUrl + "/rest/v1/rpc/" + fn;
        HttpRequest req = ctx.http.build("POST", url, Extract.credsFor(inst),
                Map.of("Content-Type", "application/json"), "{}");
        ctx.api.repeater().sendToRepeater(req, "SupaScan RPC " + fn);
        host.status("Sent RPC " + fn + " to Repeater.");
    }

    @Override
    public void refresh(SupabaseInstance current) {
        model.setRowCount(0);
        if (current == null) {
            return;
        }
        for (Map.Entry<String, RpcState> e : current.rpcStates.entrySet()) {
            RpcState st = e.getValue();
            model.addRow(new Object[] {
                    st.name,
                    st.status == null ? "" : st.status,
                    st.exposed ? "yes" : "no",
                    st.elevated ? "ELEVATED" : ""});
        }
        // Observed-but-untested RPCs.
        for (String fn : current.rpcs) {
            if (!current.rpcStates.containsKey(fn)) {
                model.addRow(new Object[] {fn, "", "untested", Wordlists.isElevatedRpc(fn) ? "ELEVATED" : ""});
            }
        }
    }
}
