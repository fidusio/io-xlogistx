package io.xlogistx.nosneak.app;

import javax.swing.*;

import com.formdev.flatlaf.FlatLightLaf;
import io.xlogistx.nosneak.app.mock.AppShell;
import io.xlogistx.nosneak.app.mock.MenuBarFactory;
import io.xlogistx.nosneak.app.mock.utility.AppContext;

public class Main {
    static void main(String... args) {
        FlatLightLaf.setup();

        // Sets default MacOS menu location (if Mac)
        /*
        if(ServerUtil.isMacOS()) {
            System.setProperty("apple.laf.useScreenMenuBar", "true");
        }
         */

        SwingUtilities.invokeLater(() -> new AppFrame().setVisible(true));
    }

    public static class AppFrame extends JFrame {
        public AppFrame() {
            setTitle("NoSneak");
            setDefaultCloseOperation(EXIT_ON_CLOSE);
            setSize(800, 600);
            setLocationRelativeTo(null);

            AppContext ctx = new AppContext();

            JMenuBar menuBar = new MenuBarFactory().buildMenu(ctx);
            menuBar.setVisible(false);
            setJMenuBar(menuBar);

            ctx.session().onAuthChange(e -> menuBar.setVisible((boolean) e.getNewValue()));

            setContentPane(new AppShell(ctx));
        }
    }
}
