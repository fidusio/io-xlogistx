package io.xlogistx.editor.pdf;

import io.xlogistx.gui.pdf.PDFSecurity;
import io.xlogistx.gui.pdf.PDFViewerPanel;
import org.zoxweb.shared.util.SUS;

/**
 * Undoable change of the document's password protection (the passwords and
 * permissions the file is saved with, see {@link PDFSecurity}). Nothing on the
 * pages changes: apply and revert hand the value to
 * {@link PDFViewerPanel#setSecurityDirect}, which uses it at the next save.
 */
public final class SetSecurityEdit implements PDFEdit {

    private final PDFViewerPanel panel;
    private final PDFSecurity before;
    private final PDFSecurity after;

    /**
     * @param panel  the panel showing the document, never null
     * @param before the protection now, null = {@link PDFSecurity#NONE}
     * @param after  the protection wanted, null = {@link PDFSecurity#NONE}
     */
    public SetSecurityEdit(PDFViewerPanel panel, PDFSecurity before, PDFSecurity after) {
        SUS.checkIfNull("panel null", panel);
        this.panel = panel;
        this.before = before == null ? PDFSecurity.NONE : before;
        this.after = after == null ? PDFSecurity.NONE : after;
    }

    /** @return the protection this edit installs */
    public PDFSecurity getAfter() {
        return after;
    }

    /** @return the protection this edit replaces */
    public PDFSecurity getBefore() {
        return before;
    }

    @Override
    public String name() {
        if (!after.isProtected())
            return "Remove document password";
        if (!before.isProtected())
            return "Set document password";
        boolean samePasswords = before.getOpenPassword().equals(after.getOpenPassword())
                && before.effectiveOwnerPassword().equals(after.effectiveOwnerPassword());
        return samePasswords ? "Change document permissions" : "Change document password";
    }

    @Override
    public void apply() {
        panel.setSecurityDirect(after);
    }

    @Override
    public void revert() {
        panel.setSecurityDirect(before);
    }

    @Override
    public int[] affectedPages() {
        return new int[0];
    }

    @Override
    public boolean structural() {
        return false;
    }
}
