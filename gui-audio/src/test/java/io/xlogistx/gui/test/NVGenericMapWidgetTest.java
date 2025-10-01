package io.xlogistx.gui.test;

import io.xlogistx.gui.NVGenericMapWidget;
import org.zoxweb.shared.util.*;

import javax.swing.*;

public class NVGenericMapWidgetTest {

    // Example enum for demo
    public enum Mode { DEV, STAGE, PROD }
    // --- Demo ---
    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                JFrame f = new JFrame("Dynamic Map Editor Panel");
                f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

                // Demo data
                NVGenericMap data = new NVGenericMap("Service Config");
//                Map<String, Object> data = new LinkedHashMap<String, Object>();
                data.build("title", "Hello world");
                data.build(new NVInt("maxUsers", 250));
                data.build(new NVLong("timeoutMs", 15000L));
                data.build(new NVDouble("threshold", 0.75d));
                data.build(new NVBoolean("enabled", Boolean.TRUE));
                data.build(new NVEnum("mode", Mode.PROD)); // enum example
                data.build(new NVFloat("precision", 0.1f));
                data.build(new NVBlob("bin", new byte[]{1,2,3,4,5,6,7,8}));

                NVGenericMapWidget panel = new NVGenericMapWidget(data);
                f.setContentPane(panel);
                f.pack();
                f.setLocationRelativeTo(null);
                f.setVisible(true);
            }
        });
    }
}
