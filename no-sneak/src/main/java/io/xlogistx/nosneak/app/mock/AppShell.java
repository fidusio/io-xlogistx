package io.xlogistx.nosneak.app.mock;


import io.xlogistx.nosneak.app.mock.utility.AppContext;
import io.xlogistx.nosneak.app.mock.utility.Navigator;

import javax.swing.*;
import java.awt.*;

public class AppShell extends JPanel {
    private final CardLayout cards = new CardLayout();
    private final JPanel content = new JPanel(cards);

    public AppShell(AppContext ctx) {
        setLayout(new BorderLayout());


        content.add(new LoginPanel(ctx), Navigator.Screen.LOGIN.name());
        content.add(new PQCRegistryPanel(), Navigator.Screen.MAIN.name());
        content.add(new SubjectPanel(), Navigator.Screen.SUBJECT.name());
        content.add(new ScanPanel(), Navigator.Screen.SCAN.name());

        add(buildContent(), BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        ctx.setNavigator(new Navigator(cards, content));
        ctx.session().onAuthChange(e -> {
            if ((boolean) e.getNewValue()) ctx.nav().show(Navigator.Screen.SUBJECT);
        });

        ctx.nav().show(Navigator.Screen.LOGIN);
    }

    private JPanel buildContent() {

        cards.show(content, "login");
        return content;
    }

    private JPanel buildFooter() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

        JLabel session = new JLabel("session: none | subject: --");
        JLabel status = new JLabel("Ready");

        footer.add(session, BorderLayout.WEST);
        footer.add(status, BorderLayout.EAST);

        return footer;
    }
}
