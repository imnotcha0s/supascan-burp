package com.supascan.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.supascan.AppContext;
import com.supascan.fingerprint.PassiveFingerprint;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/** Right-click actions on any request/response (spec §8). */
public final class SupaScanContextMenu implements ContextMenuItemsProvider {

    private final AppContext ctx;
    private final PassiveFingerprint fingerprint;
    private final SupaScanTab tab;

    public SupaScanContextMenu(AppContext ctx, PassiveFingerprint fingerprint, SupaScanTab tab) {
        this.ctx = ctx;
        this.fingerprint = fingerprint;
        this.tab = tab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> messages = collect(event);
        if (messages.isEmpty()) {
            return List.of();
        }
        List<Component> items = new ArrayList<>();

        JMenuItem add = new JMenuItem("SupaScan: Add as Supabase instance");
        add.addActionListener(e -> {
            String last = null;
            for (HttpRequestResponse m : messages) {
                String ref = fingerprint.addManualInstance(m);
                if (ref != null) {
                    last = ref;
                }
            }
            selectAndReport(last, "Added as Supabase instance");
        });

        JMenuItem analyze = new JMenuItem("SupaScan: Analyze request");
        analyze.addActionListener(e -> {
            String last = null;
            for (HttpRequestResponse m : messages) {
                String ref = fingerprint.analyzeManually(m);
                if (ref != null) {
                    last = ref;
                }
            }
            selectAndReport(last, "Analyzed");
        });

        items.add(add);
        items.add(analyze);
        return items;
    }

    private void selectAndReport(String ref, String verb) {
        if (ref != null) {
            String r = ref;
            UiUtil.edt(() -> {
                tab.selectInstance(r);
                tab.status(verb + ": " + r);
            });
        } else {
            tab.status("SupaScan: no Supabase indicators found in selection.");
        }
    }

    private List<HttpRequestResponse> collect(ContextMenuEvent event) {
        List<HttpRequestResponse> out = new ArrayList<>(event.selectedRequestResponses());
        event.messageEditorRequestResponse()
                .ifPresent(m -> out.add(m.requestResponse()));
        return out;
    }
}
