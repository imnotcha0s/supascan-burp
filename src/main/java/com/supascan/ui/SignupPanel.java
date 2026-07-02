package com.supascan.ui;

import com.supascan.AppContext;
import com.supascan.model.SessionUser;
import com.supascan.model.SupabaseInstance;
import com.supascan.net.Http;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

/** Custom signup form + raw response (spec §6.3). */
public final class SignupPanel extends JPanel implements Refreshable {

    private final AppContext ctx;
    private final SupaScanTab host;

    private final JTextField email = new JTextField(24);
    private final JTextField password = new JTextField(18);
    private final JTextArea extraData = new JTextArea(4, 40);
    private final JTextArea response = new JTextArea(12, 60);

    public SignupPanel(AppContext ctx, SupaScanTab host) {
        super(new BorderLayout(6, 6));
        this.ctx = ctx;
        this.host = host;
        email.setText("supascan.custom+{rand}@example.com");
        password.setText("Sup4!" + "changeme-" + Long.toHexString(System.nanoTime()));
        extraData.setLineWrap(true);
        response.setEditable(false);
        response.setLineWrap(true);
        response.setWrapStyleWord(true);

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 3, 3, 3);
        g.anchor = GridBagConstraints.WEST;

        g.gridx = 0; g.gridy = 0; form.add(new JLabel("Email:"), g);
        g.gridx = 1; form.add(email, g);
        g.gridx = 0; g.gridy = 1; form.add(new JLabel("Password:"), g);
        g.gridx = 1; form.add(password, g);
        g.gridx = 0; g.gridy = 2; g.anchor = GridBagConstraints.NORTHWEST;
        form.add(new JLabel("Extra data (JSON):"), g);
        g.gridx = 1; form.add(new JScrollPane(extraData), g);
        g.gridx = 1; g.gridy = 3;
        JPanel buttons = new JPanel();
        buttons.add(UiUtil.button("Signup", e -> signup()));
        buttons.add(UiUtil.button("Copy response", e -> {
            UiUtil.copy(response.getText());
            host.status("Response copied.");
        }));
        form.add(buttons, g);

        add(form, BorderLayout.NORTH);
        add(new JScrollPane(response), BorderLayout.CENTER);
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
    }

    private void signup() {
        SupabaseInstance inst = host.current();
        if (inst == null) {
            host.status("Select an instance first.");
            return;
        }
        String e = email.getText().trim().replace("{rand}", Long.toHexString(System.nanoTime()).substring(0, 8));
        String pw = password.getText();
        String data = extraData.getText().trim();
        host.runProbe(p -> {
            Http.Result r = ctx.authProbe.signup(inst, e, pw, data.isEmpty() ? null : data);
            String body = r.kind == Http.Result.Kind.OK ? r.body()
                    : "(" + r.kind + ") " + UiUtil.nz(r.error);
            UiUtil.edt(() -> response.setText("HTTP " + r.status + "\n\n" + body));
            SessionUser u = r.isOk() ? ctx.authProbe.captureSession(inst, r.body(), e, "signup") : null;
            p.update(u != null ? "Signup succeeded — session captured for " + u.label()
                    : "Signup response received (HTTP " + r.status + ").");
        });
    }

    @Override
    public void refresh(SupabaseInstance current) {
        // static form; nothing to rebuild
    }
}
