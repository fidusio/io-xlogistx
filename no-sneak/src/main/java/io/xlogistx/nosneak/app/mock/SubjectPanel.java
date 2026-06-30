package io.xlogistx.nosneak.app.mock;

import io.xlogistx.nosneak.app.mock.utility.AppContext;
import io.xlogistx.nosneak.app.mock.utility.CardStack;
import io.xlogistx.nosneak.app.mock.utility.PanelBuilder;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import java.awt.*;

public class SubjectPanel extends JPanel {
    private final CardStack cardStack = new CardStack();
    private final PanelBuilder panelBuilder = new PanelBuilder();
    private final AppContext ctx;

    // Profile text boxes
    JTextField firstName = new JTextField(20);
    JTextField lastName = new JTextField(20);
    JTextField username = new JTextField(20);
    JTextField email = new JTextField(20);
    JTextField dob = new JTextField(20);
    JTextField street = new JTextField(20);
    JTextField city = new JTextField(20);
    JTextField region = new JTextField(20);
    JTextField postCode = new JTextField(20);
    JTextField country = new JTextField(20);

    public SubjectPanel(AppContext ctx) {
        setLayout(new BorderLayout());
        this.ctx = ctx;

        cardStack.add(new JScrollPane(buildProfile()), "Profile");
        cardStack.add(new JScrollPane(buildCredentials()), "Credentials");
        cardStack.show("Profile");

        JToggleButton profileButton = new JToggleButton("Profile");
        profileButton.addActionListener(e -> cardStack.show("Profile"));
        JToggleButton credentialButton = new JToggleButton("Login credential");
        credentialButton.addActionListener(e -> cardStack.show("Credentials"));

        add(panelBuilder.buildDefaultSplitPanel(cardStack.view(), profileButton, credentialButton));
    }

    private JPanel buildProfile() {
        return panelBuilder.buildJPanelWithFields(
                new JLabel("Profile"),
                new JLabel("Details about your account. Some fields are managed by the system and can't be changed."),
                new JLabel("First name"),
                firstName,
                new JLabel("Last name"),
                lastName,
                new JLabel("Username"),
                username,
                new JLabel("Email"),
                email,
                new JLabel("Date of birth — optional"),
                dob,
                new JLabel("Mailing address"),
                new JLabel("Optional postal address for billing or shipping."),
                new JLabel("Street — optional"),
                street,
                new JLabel("City"),
                city,
                new JLabel("State / region"),
                region,
                new JLabel("Postal code"),
                postCode,
                new JLabel("Country"),
                country,
                new JButton("Save Changes")
        );
    }

    private JPanel buildCredentials() {
        JPanel p = new JPanel();
        JPanel row = PanelBuilder.row("Asdf", new JButton("asdf"));

        JPanel group = PanelBuilder.group("Test", "+ add", () -> System.out.println(""));
        group.add(row);

        p.add(group);
        return p;
    }

}