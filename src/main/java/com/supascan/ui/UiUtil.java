package com.supascan.ui;

import javax.swing.JButton;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionListener;

/** Small Swing helpers shared across panels. */
public final class UiUtil {

    private UiUtil() {
    }

    public static void copy(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(text == null ? "" : text), null);
    }

    public static JButton button(String text, ActionListener onClick) {
        JButton b = new JButton(text);
        b.addActionListener(onClick);
        return b;
    }

    public static void edt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeLater(r);
        }
    }

    /** A read-only table model. */
    public static DefaultTableModel readOnlyModel(String... columns) {
        return new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
    }

    public static JTable readOnlyTable(DefaultTableModel model) {
        JTable t = new JTable(model);
        t.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        t.getTableHeader().setReorderingAllowed(false);
        return t;
    }

    public static String nz(Object o) {
        return o == null ? "" : o.toString();
    }
}
