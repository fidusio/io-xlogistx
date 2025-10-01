package io.xlogistx.gui.test;

import io.xlogistx.gui.BooleanWidget;
import io.xlogistx.gui.DecimalWidget;
import io.xlogistx.gui.LongWidget;

import javax.swing.*;
import java.awt.*;

public class WidgetTest {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Custom Widgets Demo");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setLayout(new GridLayout(3, 1, 10, 10));
            frame.setSize(300, 200);

            // Create widgets
            BooleanWidget booleanWidget = new BooleanWidget("Enable Feature", true);
            DecimalWidget decimalWidget = new DecimalWidget("Price", 19.99);
            LongWidget longWidget = new LongWidget("Quantity", 100);

            // Add widgets to frame
            frame.add(booleanWidget);
            frame.add(decimalWidget);
            frame.add(longWidget);

            // Center frame and make visible
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }
}
