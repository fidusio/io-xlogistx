package io.xlogistx.nosneak.app.mock.utility;

public class AppContext {
    private final Session session = new Session();
    private Navigator navigator;

    public Session session() {
        return session;
    }

    public Navigator nav() {
        return navigator;
    }

    public void setNavigator(Navigator n) {
        this.navigator = n;
    }
}
