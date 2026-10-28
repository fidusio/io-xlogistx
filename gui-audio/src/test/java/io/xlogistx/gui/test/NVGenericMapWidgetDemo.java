package io.xlogistx.gui.test;

import com.formdev.flatlaf.FlatLightLaf;
import io.xlogistx.gui.NVGenericMapWidget;
import org.zoxweb.shared.util.*;

import javax.swing.*;

public class NVGenericMapWidgetDemo {

    // Example enum for demo
    public enum Mode { DEV, STAGE, PROD }
    // --- Demo ---
    public static void main(String[] args) {
        FlatLightLaf.setup();
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                JFrame f = new JFrame("Dynamic Map Editor Panel");
                f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

                // Demo data
                NVGenericMap data = new NVGenericMap("Service Config");
//                Map<String, Object> data = new LinkedHashMap<String, Object>();
                data.build("title", null);
                data.build(new NVInt("maxUsers", 250));
                data.build(new NVLong("timeoutMs", 15000L));
                data.build(new NVDouble("threshold", 0.75d));
                data.build(new NVBoolean("enabled", Boolean.TRUE));
                data.build(new NVEnum("mode", Mode.PROD)); // enum example
                data.build(new NVFloat("precision", 0.1f));
                data.build(new NVBlob("bin", new byte[]{1,2,3,4,5,6,7,8}));

                NVGenericMap data1 = new NVGenericMap("Service Config1");
//                Map<String, Object> data = new LinkedHashMap<String, Object>();
                data1.build("title", null);
                data1.build(new NVInt("maxUsers", 250));
                data1.build(new NVLong("timeoutMs", 15000L));
                data1.build(new NVDouble("threshold", 0.75d));
                data1.build(new NVBoolean("enabled", Boolean.TRUE));
                data1.build(new NVEnum("mode", Mode.PROD)); // enum example
                data1.build(new NVFloat("precision", 0.1f));
                data1.build(new NVBlob("bin", new byte[]{1,2,3,4,5,6,7,8}));
                data.build(data1);

                NVGenericMapWidget panel = new NVGenericMapWidget(data);
                f.setContentPane(panel);
                f.pack();
                f.setLocationRelativeTo(null);
                f.setVisible(true);
            }
        });
    }
}
