package io.xlogistx.nosneak.app.mock.utility;

import io.xlogistx.nosneak.app.mock.MockSecManager;
import org.zoxweb.shared.filters.FilterType;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.Arrays;

/**
 * Mock authentication/session state. Tracks whether a subject is signed in and
 * fires an {@code "authenticated"} property-change event on every login/logout so
 * the UI can react. All login/register methods are stubs for now.
 */
public class Session {
    private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);
    private final MockSecManager secManager = new MockSecManager();
    private boolean authenticated;
    private String subject;

    /**
     * @return {@code true} if a subject is currently signed in.
     */
    public boolean isAuthenticated() {
        return authenticated;
    }

    /**
     * @return the signed-in subject's id, or {@code null} when logged out.
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Mock username/password login; marks the session authenticated and fires the change event.
     *
     * @param subject  the subject id
     * @param password the password (unused by the mock)
     */
    //@TODO
    public void loginUsernamePassword(String subject, char[] password) {
        this.subject = subject;
        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);
    }

    /**
     * Mock API-key login; marks the session authenticated and fires the change event.
     *
     * @param apiKey the API key (unused by the mock)
     */
    //@TODO
    public void loginAPIKey(char[] apiKey) {
        this.subject = "";
        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);
    }

    /**
     * Mock passkey login; marks the session authenticated and fires the change event.
     */
    //@TODO
    public void loginPasskey() {
        this.subject = "";
        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);
    }

    /**
     * Mock registration: validates the password through {@code FilterType.PASSWORD},
     * then delegates to {@link #loginUsernamePassword}. Does nothing if validation fails.
     *
     * @param subject  the subject id
     * @param password the candidate password
     */
    //@TODO
    public void registerUsernamePassword(String subject, char[] password) {
        if (FilterType.PASSWORD.isValid(Arrays.toString(password))) {
            loginUsernamePassword(subject, password);
        }
    }

    /**
     * Mock API-key registration; currently just delegates to {@link #loginAPIKey}.
     *
     * @param apiKey the API key
     */
    //@TODO
    public void registerAPIKey(char[] apiKey) {
        loginAPIKey(apiKey);
    }

    /**
     * Mock passkey registration; currently just delegates to {@link #loginPasskey}.
     */
    //@TODO
    public void registerPasskey() {
        loginPasskey();
    }

    /**
     * Signs the subject out and fires the {@code "authenticated"} change event.
     */
    public void logout() {
        boolean old = this.authenticated;
        this.authenticated = false;
        this.subject = null;
        pcs.firePropertyChange("authenticated", old, false);
    }

    /**
     * Subscribes a listener to {@code "authenticated"} changes (login/logout).
     *
     * @param l the listener to notify
     */
    public void onAuthChange(PropertyChangeListener l) {
        pcs.addPropertyChangeListener("authenticated", l);
    }
}
