package com.supascan.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.supascan.AppContext;
import com.supascan.model.BucketState;
import com.supascan.model.StorageObject;
import com.supascan.model.SupabaseInstance;
import com.supascan.net.Http;
import com.supascan.probes.Wordlists;

import javax.swing.BorderFactory;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.io.File;
import java.nio.file.Files;

/** Storage enumeration UI + per-file copy URL / download / send to Repeater. */
public final class StoragePanel extends JPanel implements Refreshable {

    private final AppContext ctx;
    private final SupaScanTab host;

    private final JTextField customBuckets = new JTextField(30);
    private final DefaultTableModel bucketModel = UiUtil.readOnlyModel("Bucket", "Files");
    private final JTable bucketTable = UiUtil.readOnlyTable(bucketModel);
    private final DefaultTableModel fileModel = UiUtil.readOnlyModel("Path", "Size", "Mimetype");
    private final JTable fileTable = UiUtil.readOnlyTable(fileModel);

    public StoragePanel(AppContext ctx, SupaScanTab host) {
        super(new BorderLayout(6, 6));
        this.ctx = ctx;
        this.host = host;
        bucketTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        fileTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        bucketTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showFiles();
            }
        });

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Extra bucket names (comma/space separated):"));
        top.add(customBuckets);
        top.add(UiUtil.button("List objects", e -> listObjects()));

        JPanel fileButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fileButtons.add(UiUtil.button("Copy public URL", e -> copyUrl()));
        fileButtons.add(UiUtil.button("Download", e -> download()));
        fileButtons.add(UiUtil.button("Send to Repeater", e -> sendToRepeater()));

        JPanel filesPanel = new JPanel(new BorderLayout());
        filesPanel.add(new JScrollPane(fileTable), BorderLayout.CENTER);
        filesPanel.add(fileButtons, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(bucketTable), filesPanel);
        split.setResizeWeight(0.35);

        add(top, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
    }

    private void listObjects() {
        SupabaseInstance inst = host.current();
        if (inst == null) {
            return;
        }
        var custom = Wordlists.parse(customBuckets.getText());
        host.runProbe(p -> ctx.storageProbe.run(inst, custom, p));
    }

    private BucketState selectedBucket() {
        SupabaseInstance inst = host.current();
        int row = bucketTable.getSelectedRow();
        if (inst == null || row < 0) {
            return null;
        }
        return inst.bucketStates.get((String) bucketModel.getValueAt(row, 0));
    }

    private StorageObject selectedFile() {
        BucketState bs = selectedBucket();
        int row = fileTable.getSelectedRow();
        if (bs == null || row < 0 || row >= bs.files.size()) {
            return null;
        }
        return bs.files.get(row);
    }

    private void showFiles() {
        fileModel.setRowCount(0);
        BucketState bs = selectedBucket();
        if (bs == null) {
            return;
        }
        for (StorageObject o : bs.files) {
            fileModel.addRow(new Object[] {o.path, o.size == null ? "" : o.size, UiUtil.nz(o.mimetype)});
        }
    }

    private void copyUrl() {
        SupabaseInstance inst = host.current();
        BucketState bs = selectedBucket();
        StorageObject f = selectedFile();
        if (inst != null && bs != null && f != null) {
            UiUtil.copy(ctx.storageProbe.publicUrl(inst, bs.name, f.path));
            host.status("Public URL copied.");
        }
    }

    private void download() {
        SupabaseInstance inst = host.current();
        BucketState bs = selectedBucket();
        StorageObject f = selectedFile();
        if (inst == null || bs == null || f == null) {
            return;
        }
        host.runProbe(p -> {
            Http.Result r = ctx.storageProbe.download(inst, bs.name, f.path);
            if (r.kind == Http.Result.Kind.OUT_OF_SCOPE) {
                p.update("Download: " + r.error);
                return;
            }
            if (!r.isOk() || r.rr == null || !r.rr.hasResponse()) {
                p.update("Download failed (HTTP " + r.status + ").");
                return;
            }
            byte[] bytes = r.rr.response().body().getBytes();
            UiUtil.edt(() -> saveBytes(f.path, bytes));
            p.update("Downloaded " + f.path + " (" + bytes.length + " bytes).");
        });
    }

    private void saveBytes(String path, byte[] bytes) {
        JFileChooser chooser = new JFileChooser();
        String name = path.contains("/") ? path.substring(path.lastIndexOf('/') + 1) : path;
        chooser.setSelectedFile(new File(name));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                Files.write(chooser.getSelectedFile().toPath(), bytes);
                host.status("Saved to " + chooser.getSelectedFile().getAbsolutePath());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Save failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void sendToRepeater() {
        SupabaseInstance inst = host.current();
        BucketState bs = selectedBucket();
        StorageObject f = selectedFile();
        if (inst == null || bs == null || f == null) {
            return;
        }
        HttpRequest req = ctx.storageProbe.downloadRequest(inst, bs.name, f.path);
        ctx.api.repeater().sendToRepeater(req, "SupaScan storage " + f.path);
        host.status("Sent to Repeater.");
    }

    @Override
    public void refresh(SupabaseInstance current) {
        bucketModel.setRowCount(0);
        if (current == null) {
            return;
        }
        for (String bucket : current.buckets) {
            BucketState bs = current.bucketStates.get(bucket);
            bucketModel.addRow(new Object[] {bucket, bs == null ? "?" : bs.fileCount});
        }
        showFiles();
    }
}
