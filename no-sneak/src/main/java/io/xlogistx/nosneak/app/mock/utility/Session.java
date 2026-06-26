package io.xlogistx.nosneak.app.mock.utility;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;

public class Session {
    private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);
    private boolean authenticated;
    private String subject;

    public boolean isAuthenticated() {
        return authenticated;
    }

    public String getSubject() {
        return subject;
    }

    //@TODO
    public void loginUsernamePassword(String subject, char[] password) {
        this.subject = subject;
        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);
    }

    //@TODO
    public void loginAPIKey(char[] apiKey) {
        this.subject = "";
        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);
    }

    //@TODO
    public void loginPasskey() {
        this.subject = "";
        boolean old = this.authenticated;
        this.authenticated = true;
        pcs.firePropertyChange("authenticated", old, true);
    }

    //@TODO
    public void registerUsernamePassword(String subject, char[] password) {
        loginUsernamePassword(subject, password);
    }

    //@TODO
    public void registerAPIKey(char[] apiKey) {
        loginAPIKey(apiKey);
    }

    //@TODO
    public void registerPasskey() {
        loginPasskey();
    }

    public void logout() {
        boolean old = this.authenticated;
        this.authenticated = false;
        this.subject = null;
        pcs.firePropertyChange("authenticated", old, false);
    }

    public void onAuthChange(PropertyChangeListener l) {
        pcs.addPropertyChangeListener("authenticated", l);
    }
}
