package io.xlogistx.nosneak.app.mock;

import io.xlogistx.gui.TreeTextWidget;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

public class PQCRegistryPanel extends JPanel {
    public PQCRegistryPanel() {
        setLayout(new BorderLayout());

        TreeTextWidget files = new TreeTextWidget("root");

        DefaultTableModel model = new DefaultTableModel();
        model.addColumn("Public Key");
        model.addColumn("Documents");
        JTable globalRegistry = new JTable(model);

        JSplitPane content = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, files, new JScrollPane(globalRegistry));

        add(content, BorderLayout.CENTER);

    }
}
