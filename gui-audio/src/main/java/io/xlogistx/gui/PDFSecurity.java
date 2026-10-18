package io.xlogistx.gui;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.PDEncryption;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;

import java.io.IOException;

/**
 * The password protection of a PDF document as one immutable value: the
 * password that opens it (the standard "user" password, empty = anyone can
 * open it), the owner password (empty = the same as the open password) and
 * the permissions a reader opening with the open password gets. {@link #NONE}
 * is an unprotected document.
 * <p>
 * {@link #applyTo(PDDocument)} installs the value on a document for its next
 * save: AES-256 with the two passwords and the permissions, or the removal of
 * any existing encryption for {@link #NONE}. PDFBox refuses to save a document
 * that was loaded encrypted unless one of the two is done; {@link PDFViewerPanel}
 * keeps the value it got from {@link #loaded(PDDocument, String)} when it opened
 * such a document and applies it, to a copy, when it saves.
 */
public final class PDFSecurity {

    /** No password, no restrictions. */
    public static final PDFSecurity NONE = new PDFSecurity("", "", new AccessPermission());

    private final String openPassword;
    private final String ownerPassword;
    private final int permissionBits;

    private PDFSecurity(String openPassword, String ownerPassword, AccessPermission permissions) {
        this.openPassword = openPassword == null ? "" : openPassword;
        this.ownerPassword = ownerPassword == null ? "" : ownerPassword;
        this.permissionBits = permissions.getPermissionBytes();
    }

    /**
     * @param openPassword  the password that opens the document, null or empty for none
     * @param ownerPassword the owner password, null or empty = the same as the open password
     * @param permissions   what a reader opening with the open password may do, null = everything
     * @return the value; {@link #NONE} when both passwords are empty and everything is allowed
     */
    public static PDFSecurity of(String openPassword, String ownerPassword, AccessPermission permissions) {
        PDFSecurity s = new PDFSecurity(openPassword, ownerPassword, permissions == null ? new AccessPermission() : permissions);
        return s.isProtected() ? s : NONE;
    }

    /**
     * The protection of a document that was just loaded with {@code password}:
     * that password opens it, it also stands in for the owner password (the
     * original one is not recoverable), and the permissions are the ones
     * stored in the file.
     *
     * @param doc      the loaded document
     * @param password the password it was opened with, "" when none was needed
     * @return the value, {@link #NONE} when the document is not encrypted
     */
    public static PDFSecurity loaded(PDDocument doc, String password) {
        if (!doc.isEncrypted())
            return NONE;
        PDEncryption enc = doc.getEncryption();
        AccessPermission ap = new AccessPermission(enc.getPermissions());
        return of(password, password, ap);
    }

    /** @return the password that opens the document, "" when none is needed */
    public String getOpenPassword() {
        return openPassword;
    }

    /** @return the owner password, "" when it is the open password */
    public String getOwnerPassword() {
        return ownerPassword;
    }

    /** @return the owner password as used for encryption: the open password when none was given */
    public String effectiveOwnerPassword() {
        return ownerPassword.isEmpty() ? openPassword : ownerPassword;
    }

    /** @return a fresh copy of the permissions (the standard bits) */
    public AccessPermission getPermissions() {
        return new AccessPermission(permissionBits);
    }

    /** @return true when a password is needed to open the document */
    public boolean needsPasswordToOpen() {
        return !openPassword.isEmpty();
    }

    /** @return true when the document is encrypted at all (a password or a restriction) */
    public boolean isProtected() {
        return !openPassword.isEmpty() || !ownerPassword.isEmpty() || !allAllowed();
    }

    /** @return true when the permissions forbid nothing */
    public boolean allAllowed() {
        return permissionBits == new AccessPermission().getPermissionBytes();
    }

    /**
     * Installs this value on a document for its next save: encrypts with
     * AES-256 (the two passwords, the permissions), or strips the encryption
     * for {@link #NONE}. <b>Apply it to a throwaway copy</b>: PDFBox encrypts
     * the streams and strings <i>in memory</i> while it writes, so a document
     * saved encrypted is unusable afterwards ({@link PDFViewerPanel} saves a
     * protected document through a copy for that reason).
     *
     * @throws IOException when PDFBox refuses the policy
     */
    public void applyTo(PDDocument doc) throws IOException {
        if (!isProtected()) {
            doc.setAllSecurityToBeRemoved(true);
            return;
        }
        StandardProtectionPolicy policy = new StandardProtectionPolicy(effectiveOwnerPassword(), openPassword, getPermissions());
        policy.setEncryptionKeyLength(256);
        policy.setPreferAES(true);
        doc.protect(policy);
    }

    /** @return a one-line description for dialogs and status text, e.g. "Password to open; printing not allowed" */
    public String describe() {
        if (!isProtected())
            return "No password";
        StringBuilder sb = new StringBuilder();
        if (needsPasswordToOpen())
            sb.append("Password to open");
        else
            sb.append("Opens without a password");
        if (!ownerPassword.isEmpty() && !ownerPassword.equals(openPassword))
            sb.append(", separate owner password");
        AccessPermission ap = getPermissions();
        if (!ap.canPrint())
            sb.append("; printing not allowed");
        if (!ap.canExtractContent())
            sb.append("; copying not allowed");
        if (!ap.canModify())
            sb.append("; changes not allowed");
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof PDFSecurity))
            return false;
        PDFSecurity s = (PDFSecurity) o;
        return openPassword.equals(s.openPassword) && ownerPassword.equals(s.ownerPassword) && permissionBits == s.permissionBits;
    }

    @Override
    public int hashCode() {
        return (openPassword.hashCode() * 31 + ownerPassword.hashCode()) * 31 + permissionBits;
    }

    @Override
    public String toString() {
        return "PDFSecurity[" + describe() + "]";
    }
}
