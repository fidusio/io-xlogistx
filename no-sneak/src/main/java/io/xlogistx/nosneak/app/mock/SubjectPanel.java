package io.xlogistx.nosneak.app.mock;

import io.xlogistx.nosneak.app.mock.utility.PaneBuilder;

import javax.swing.*;
import java.awt.*;

public class SubjectPanel extends JPanel {
    private final CardLayout cards = new CardLayout();
    private final JPanel content = new JPanel(cards);
    private PaneBuilder paneBuilder = new PaneBuilder();

    public SubjectPanel() {
        setLayout(new BorderLayout());

        content.add(buildProfile(), "Profile");
        content.add(buildPrincipalIDs(), "Principals");
        content.add(buildCredentials(), "Credentials");
        showCard("Profile");

        // left side that shows menus
        JPanel options = new JPanel();
        options.setLayout(new GridLayout(0, 1, 0, 8));

        ButtonGroup group = new ButtonGroup();

        JToggleButton profileButton = new JToggleButton("Profile");
        profileButton.addActionListener(e -> showCard("Profile"));
        JToggleButton principalIDButton = new JToggleButton("Principal IDs");
        principalIDButton.addActionListener(e -> showCard("Principals"));
        JToggleButton credentialButton = new JToggleButton("Login credential");
        credentialButton.addActionListener(e -> showCard("Credentials"));

        group.add(profileButton);
        group.add(principalIDButton);
        group.add(credentialButton);
        profileButton.setSelected(true);

        options.add(profileButton);
        options.add(principalIDButton);
        options.add(credentialButton);

        JPanel optionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        optionsRow.add(options);
        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.add(optionsRow, BorderLayout.NORTH);


        // right side that shows selections
        JPanel view = new JPanel(new BorderLayout());
        view.add(content, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(sidebar), new JScrollPane(view));
        split.setDividerLocation(140);
        split.setResizeWeight(0);
        add(split, BorderLayout.CENTER);
    }

    private void showCard(String name) {
        cards.show(content, name);
    }

    private JPanel buildProfile() {
        return paneBuilder.buildJPanelWithFields(
                new JLabel("Profile"),
                new JLabel("Details about your account. Some fields are managed by the system and can't be changed."),
                new JLabel("First name"),
                new JTextField(20),
                new JLabel("Last name"),
                new JTextField(20),
                new JLabel("Email"),
                new JTextField(20),
                new JLabel("Date of birth — optional"),
                new JTextField(20),
                new JLabel("Description — optional"),
                new JTextField(20),
                new JLabel("Canonical ID"),
                new JTextField(20),
                new JButton("Save Changes")
        );
    }

    private JPanel buildPrincipalIDs() {
        // get user principal ids then display them
        JButton placeholder1 = new JButton("placeholder");
        JButton placeholder2 = new JButton("placeholder");
        JButton placeholder3 = new JButton("placeholder");
        JButton addPrincipal = new JButton("+ Add principal ID");

        return paneBuilder.buildJPanelWithFields(
                new JLabel("Principal IDs"),
                new JLabel("Email addresses and handles that resolve to this subject."),
                placeholder1,
                placeholder2,
                placeholder3,
                addPrincipal
        );
    }

    private JPanel buildCredentials() {
        JButton placeholder1 = new JButton("placeholder");
        JButton placeholder2 = new JButton("placeholder");
        JButton placeholder3 = new JButton("placeholder");
        JButton addLogin = new JButton("+ Add login method");

        return paneBuilder.buildJPanelWithFields(
                new JLabel("Login credentials"),
                new JLabel("Ways you sign in. You can register more than one."),
                placeholder1,
                placeholder2,
                placeholder3,
                addLogin
        );
    }

}
