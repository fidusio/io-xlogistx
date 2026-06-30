package io.xlogistx.nosneak.app;

import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.fonts.roboto.FlatRobotoFont;
import io.xlogistx.nosneak.app.mock.AppShell;
import io.xlogistx.nosneak.app.mock.MenuBarFactory;
import io.xlogistx.nosneak.app.mock.utility.AppContext;
import org.zoxweb.server.security.MockDomainSecurityManager;
import org.zoxweb.shared.security.DomainSecurityManager;

import javax.swing.*;
import java.awt.*;

public class Main {
    static void main(String... args) {
        FlatRobotoFont.install();
        FlatLightLaf.setup();
        FlatLaf.registerCustomDefaultsSource("themes");
        UIManager.put("defaultFont", new Font(FlatRobotoFont.FAMILY, Font.PLAIN, 13));

        SwingUtilities.invokeLater(() -> new AppFrame().setVisible(true));
    }

    public static class AppFrame extends JFrame {
        public AppFrame() {
            setTitle("NoSneak");
            setDefaultCloseOperation(EXIT_ON_CLOSE);
            setSize(800, 600);
            setLocationRelativeTo(null);

            DomainSecurityManager domainSecurityManager = new MockDomainSecurityManager();

            AppContext ctx = new AppContext(domainSecurityManager);

            JMenuBar menuBar = new MenuBarFactory().buildMenu(ctx);
            menuBar.setVisible(false);
            setJMenuBar(menuBar);

            ctx.session().onAuthChange(e -> menuBar.setVisible((boolean) e.getNewValue()));

            setContentPane(new AppShell(ctx));
        }
    }
}
