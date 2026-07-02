package com.supascan.ui;

import com.supascan.AppContext;
import com.supascan.extract.Extract;
import com.supascan.model.SessionUser;
import com.supascan.model.SupabaseInstance;
import com.supascan.net.Http;
import com.supascan.registry.Registry;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.GridLayout;

/** Manage identities (anon + users) and add sessions by sign-in or raw token. */
public final class SessionsPanel extends JPanel implements Refreshable {

    private final AppContext ctx;
    private final SupaScanTab host;

    private final DefaultTableModel model =
            UiUtil.readOnlyModel("Active", "Identity", "Source", "Token");
    private final JTable table = UiUtil.readOnlyTable(model);

    private final JTextField emailField = new JTextField(18);
    private final JPasswordField passwordField = new JPasswordField(14);
    private final JTextField tokenField = new JTextField(28);

    public SessionsPanel(AppContext ctx, SupaScanTab host) {
        super(new BorderLayout(6, 6));
        this.ctx = ctx;
        this.host = host;
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JPanel buttons = new JPanel();
        buttons.add(UiUtil.button("Set active", e -> setActive()));
        buttons.add(UiUtil.button("Remove", e -> remove()));

        JPanel top = new JPanel(new BorderLayout());
        top.add(new JScrollPane(table), BorderLayout.CENTER);
        top.add(buttons, BorderLayout.SOUTH);

        add(top, BorderLayout.CENTER);
        add(buildForms(), BorderLayout.SOUTH);
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
    }

    private JPanel buildForms() {
        JPanel forms = new JPanel(new GridLayout(2, 1, 4, 4));

        JPanel signIn = new JPanel();
        signIn.setBorder(BorderFactory.createTitledBorder("Add by sign-in (password grant)"));
        signIn.add(new JLabel("Email:"));
        signIn.add(emailField);
        signIn.add(new JLabel("Password:"));
        signIn.add(passwordField);
        JButton signInBtn = UiUtil.button("Sign in", e -> signIn());
        signIn.add(signInBtn);

        JPanel addToken = new JPanel();
        addToken.setBorder(BorderFactory.createTitledBorder("Add by token (paste a JWT)"));
        addToken.add(new JLabel("JWT:"));
        addToken.add(tokenField);
        addToken.add(UiUtil.button("Add token", e -> addToken()));

        forms.add(signIn);
        forms.add(addToken);
        return forms;
    }

    private void setActive() {
        SupabaseInstance inst = host.current();
        int row = table.getSelectedRow();
        if (inst == null || row < 0) {
            return;
        }
        if (row == 0) {
            inst.activeSessionId = null; // Anonymous
        } else {
            SessionUser u = userForRow(inst, row);
            if (u != null) {
                inst.activeSessionId = u.id;
            }
        }
        ctx.registry.save(inst);
        host.refreshAll();
    }

    private void remove() {
        SupabaseInstance inst = host.current();
        int row = table.getSelectedRow();
        if (inst == null || row <= 0) {
            return; // row 0 is Anonymous
        }
        SessionUser u = userForRow(inst, row);
        if (u != null) {
            inst.sessions.remove(u);
            if (u.id.equals(inst.activeSessionId)) {
                inst.activeSessionId = null;
            }
            ctx.registry.save(inst);
            host.refreshAll();
        }
    }

    private void signIn() {
        SupabaseInstance inst = host.current();
        if (inst == null) {
            return;
        }
        String email = emailField.getText().trim();
        String password = new String(passwordField.getPassword());
        if (email.isEmpty() || password.isEmpty()) {
            host.status("Enter email and password.");
            return;
        }
        host.runProbe(p -> {
            Http.Result r = ctx.authProbe.signIn(inst, email, password);
            if (r.kind == Http.Result.Kind.OUT_OF_SCOPE) {
                p.update("Sign-in: " + r.error);
                return;
            }
            if (r.isOk() && ctx.authProbe.captureSession(inst, r.body(), email, "signin") != null) {
                p.update("Signed in as " + email);
            } else {
                p.update("Sign-in failed (HTTP " + (r.status) + ").");
            }
        });
    }

    private void addToken() {
        SupabaseInstance inst = host.current();
        if (inst == null) {
            return;
        }
        String token = tokenField.getText().trim();
        Extract.Jwt jwt = Extract.decodeJwt(token);
        if (jwt == null) {
            JOptionPane.showMessageDialog(this, "Not a decodable JWT.", "Invalid token",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (jwt.isServiceRole()) {
            int choice = JOptionPane.showConfirmDialog(this,
                    "This token has role \"service_role\" — it bypasses all Row Level Security.\n"
                            + "Active checks run as this identity will use it for every request.\n\n"
                            + "Add it anyway?",
                    "service_role token", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) {
                return;
            }
            ctx.api.logging().logToOutput(
                    "SupaScan: operator manually added a service_role session for " + inst.projectRef);
        }
        SessionUser u = new SessionUser(
                jwt.sub != null ? jwt.sub : Registry.newId(),
                jwt.email, jwt.token, "manual", Registry.now());
        inst.sessions.add(u);
        inst.activeSessionId = u.id;
        ctx.registry.save(inst);
        tokenField.setText("");
        host.refreshAll();
        host.status("Token added as active identity (" + u.label() + ").");
    }

    private SessionUser userForRow(SupabaseInstance inst, int row) {
        int idx = row - 1; // row 0 = Anonymous
        return (idx >= 0 && idx < inst.sessions.size()) ? inst.sessions.get(idx) : null;
    }

    @Override
    public void refresh(SupabaseInstance current) {
        model.setRowCount(0);
        if (current == null) {
            return;
        }
        model.addRow(new Object[] {
                current.activeSessionId == null ? "●" : "", "Anonymous",
                current.anonKey != null ? "anon key" : "(no anon key)", ""});
        for (SessionUser u : current.sessions) {
            model.addRow(new Object[] {
                    u.id.equals(current.activeSessionId) ? "●" : "",
                    u.label(), UiUtil.nz(u.source), preview(u.token)});
        }
    }

    private static String preview(String token) {
        if (token == null) {
            return "";
        }
        return token.length() > 14 ? token.substring(0, 14) + "…" : token;
    }
}
