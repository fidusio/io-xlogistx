package io.xlogistx.gui.test;

import com.formdev.flatlaf.FlatLightLaf;
import io.xlogistx.gui.BadgeLabel;
import io.xlogistx.gui.DirectoryField;
import io.xlogistx.gui.FormPanel;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.InlineMessage;
import io.xlogistx.gui.SplashSidePanel;
import io.xlogistx.gui.StepperPanel;
import io.xlogistx.gui.UITokens;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;

/**
 * Visual check of the sign-in primitives together: a {@link SplashSidePanel} on the left and a
 * two-step {@link StepperPanel} card on the right, whose first step is a {@link FormPanel} with
 * a {@link DirectoryField}, a hidden "first run" group that appears when the chosen directory has
 * no {@code marker.txt}, and an {@link InlineMessage}. Completing step 1 collapses it to a
 * summary with a Change button and activates step 2.
 */
public class StepperPanelDemo {

    public static void main(String[] args) {
        FlatLightLaf.setup();
        SwingUtilities.invokeLater(StepperPanelDemo::show);
    }

    private static void show() {
        JFrame f = new JFrame("StepperPanel demo");
        f.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        SplashSidePanel splash = new SplashSidePanel(
                IconUtil.svgIcon("io/xlogistx/gui/icons/shield.svg", 26, new Color(0xA9A8F0)),
                "Demo App",
                "What does your network expose, and how good is its posture?",
                "TLS and post-quantum readiness, certificate trust, running services and live hosts.",
                Arrays.asList(
                        "Scans run from this machine under its own address.",
                        "Results stay in a local encrypted store opened with your own vault password.",
                        "The assistant only sees a report when you attach it."),
                "Demo 0.1 · Java " + System.getProperty("java.version"));

        StepperPanel steps = new StepperPanel();

        // step 1
        FormPanel open = new FormPanel();
        DirectoryField dir = new DirectoryField().dialogTitle("Choose the store directory").placeholder("No directory chosen");
        InlineMessage mode = new InlineMessage();
        JPasswordField vault = new JPasswordField();
        vault.putClientProperty("JTextField.showRevealButton", true);
        JButton openButton = new JButton("Open");
        open.field("Location", dir);
        open.row(mode, "growx");
        open.field("Vault password", vault);
        open.group("firstRun", () -> {
            open.requiredField("Operator username", new JTextField());
            open.requiredField("Operator password", new JPasswordField());
            open.field("Database password", new JPasswordField(), "Empty = generated and kept only in the vault");
        });
        open.showGroup("firstRun", false);
        JPanel actions = new JPanel(new MigLayout("insets 0", "[grow][]"));
        actions.setOpaque(false);
        actions.add(new JLabel(), "growx");
        actions.add(openButton);
        open.row(actions);
        dir.onChange(chosen -> {
            boolean create = !new java.io.File(chosen, "marker.txt").exists();
            open.showGroup("firstRun", create);
            openButton.setText(create ? "Create" : "Open");
            mode.info(create ? "No marker here: a new store would be created." : "Existing store found: enter its password.");
        });
        int one = steps.addStep("Open store", "Where the application keeps its data", open);

        // step 2
        FormPanel sign = new FormPanel();
        JTextField user = new JTextField();
        JPasswordField pwd = new JPasswordField();
        pwd.putClientProperty("JTextField.showRevealButton", true);
        InlineMessage signMsg = new InlineMessage();
        JButton signIn = new JButton("Sign in");
        sign.field("Username", user);
        sign.field("Password", pwd);
        sign.row(signMsg, "growx");
        JPanel signActions = new JPanel(new MigLayout("insets 0", "[grow][]"));
        signActions.setOpaque(false);
        signActions.add(new JLabel("<html><a href='#'>Create another account</a></html>"), "growx");
        signActions.add(signIn);
        sign.row(signActions);
        int two = steps.addStep("Sign in", "Your account in this store", sign);
        steps.setStepEnabled(two, false);

        openButton.addActionListener(e -> {
            if (dir.getDirectory() == null) {
                mode.error("Please choose a location.");
                return;
            }
            mode.clear();
            steps.complete(one, dir.getDirectory().getAbsolutePath() + " · vault unlocked", () -> {
                steps.reopen(one);
                steps.setStepEnabled(two, false);
            });
            steps.setStepEnabled(two, true);
            steps.activate(two);
            user.requestFocusInWindow();
        });
        signIn.addActionListener(e -> {
            if (user.getText().trim().isEmpty()) signMsg.error("Username is required.");
            else signMsg.ok("Signed in as " + user.getText().trim());
        });

        JPanel card = new JPanel(new MigLayout("insets 32 36 32 36, fillx", "[grow,fill]"));
        card.setBackground(UITokens.surface());
        card.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        card.add(steps, "growx");
        JPanel badges = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        badges.setOpaque(false);
        badges.add(new BadgeLabel("vault unlocked", IconUtil.svgIcon("io/xlogistx/gui/icons/lock.svg", 12, UITokens.ok()), BadgeLabel.Tone.OK));
        badges.add(new BadgeLabel("super-admin", BadgeLabel.Tone.NEUTRAL));
        badges.add(new BadgeLabel("A · Hybrid PQC", BadgeLabel.Tone.OK));
        badges.add(new BadgeLabel("C · Not ready", BadgeLabel.Tone.WARN));
        badges.add(new BadgeLabel("D · Weak", BadgeLabel.Tone.DANGER));
        badges.add(new BadgeLabel("md skill", BadgeLabel.Tone.ACCENT));
        card.add(badges, "growx, gaptop 16");

        JPanel right = new JPanel(new MigLayout("insets 40 24 40 24, fill", "[grow,center]", "[grow,center]"));
        right.setBackground(new Color(0xF4F4F7));
        right.add(card, "wmin 420, wmax 520, growx");

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, splash, right);
        split.setDividerLocation(480);
        split.setResizeWeight(0.35);
        f.setContentPane(split);
        f.setSize(1280, 800);
        f.setLocationRelativeTo(null);
        f.setVisible(true);
    }
}
