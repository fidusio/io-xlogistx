package io.xlogistx.nosneak.app.mock.utility;

import javax.swing.*;
import java.awt.*;
import java.io.Serializable;

public class PaneBuilder  {
    public PaneBuilder() {
    }

    public JPanel buildJPanelWithFields(JComponent... fields) {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 6, 6, 6);
        c.fill = GridBagConstraints.HORIZONTAL;

        c.gridx = 0;
        c.gridwidth = 3;

        for (int i = 0; i < fields.length; i++) {
            c.gridy = i;
            panel.add(fields[i], c);
        }

        return panel;
    }
}