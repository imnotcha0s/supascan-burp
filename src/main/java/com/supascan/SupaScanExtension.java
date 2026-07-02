package com.supascan;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.supascan.fingerprint.PassiveFingerprint;
import com.supascan.ui.SupaScanContextMenu;
import com.supascan.ui.SupaScanTab;

/**
 * SupaScan — passively fingerprints Supabase backends in proxied traffic and
 * runs non-destructive, scope-gated checks for Supabase misconfigurations.
 *
 * <p>Burp auto-detects the single class implementing {@link BurpExtension}; no
 * manifest attribute is required.
 */
public class SupaScanExtension implements BurpExtension {

    public static final String NAME = "SupaScan";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);

        AppContext ctx = new AppContext(api);

        // §3 passive detection over all Proxy traffic (never sends a request).
        PassiveFingerprint fingerprint = new PassiveFingerprint(api, ctx.registry, ctx.findings);
        api.http().registerHttpHandler(fingerprint);

        // §8 UI: the suite tab + right-click actions.
        SupaScanTab tab = new SupaScanTab(ctx);
        api.userInterface().registerSuiteTab(NAME, tab.component());
        api.userInterface().registerContextMenuItemsProvider(
                new SupaScanContextMenu(ctx, fingerprint, tab));

        // Flush/persist and stop the executor on unload.
        api.extension().registerUnloadingHandler(ctx::shutdown);

        api.logging().logToOutput(NAME + " loaded. Passive detection is active on Proxy traffic; "
                + "active checks are opt-in and gated behind Burp scope.");
    }
}
