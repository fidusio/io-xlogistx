package io.xlogistx.gui.test;

import io.xlogistx.gui.IconWidget;

import javax.swing.*;
import java.awt.*;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class StateIconDemo {


    /**
     * StateIcon is a custom Icon that changes its appearance based on the current state.
     * It maps state names to specific Icon instances.
     */
    public class StateIcon implements Icon {
        private Icon currentIcon;
        private final Map<String, Icon> iconMap = new HashMap<>();

        /**
         * Constructs a StateIcon with a default icon.
         *
         * @param defaultIcon The default icon to display.
         */
        public StateIcon(Icon defaultIcon) {
            this.currentIcon = defaultIcon;
        }

        /**
         * Maps a state name to an Icon.
         *
         * @param state The name of the state.
         * @param icon  The Icon associated with the state.
         */
        public void mapState(String state, Icon icon) {
            iconMap.put(state, icon);
        }

        /**
         * Sets the current state and updates the icon accordingly.
         *
         * @param state The new state name.
         * @return true if the state was mapped and set successfully, false otherwise.
         */
        public boolean setState(String state) {
            Icon icon = iconMap.get(state);
            if (icon != null) {
                this.currentIcon = icon;
                return true;
            }
            return false;
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            if (currentIcon != null) {
                currentIcon.paintIcon(c, g, x, y);
            }
        }

        @Override
        public int getIconWidth() {
            return currentIcon != null ? currentIcon.getIconWidth() : 0;
        }

        @Override
        public int getIconHeight() {
            return currentIcon != null ? currentIcon.getIconHeight() : 0;
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                // Create the main frame
                JFrame frame = new JFrame("StateIcon Demo");
                frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                frame.setSize(400, 300);
                frame.setLayout(new FlowLayout());

                // Load icons for different states
                Icon xlogistxIcon = new ImageIcon(new URL("https://xlogistx.io/favicon.ico")); // Custom CircleIcon from previous example
                Icon googleIcon = new ImageIcon("/google.ico");

                Icon youtubeIcon = new ImageIcon("/youtube.ico");

                // Create StateIcon with default state "OFF"
                IconWidget stateIcon = new IconWidget(40,40);
                stateIcon.mapStatus("youtube", youtubeIcon)
                        .mapStatus("xlogistx", xlogistxIcon)
                        .mapStatus("google", googleIcon);

                stateIcon.setStatus("google");

                System.out.println(xlogistxIcon +"\n" + googleIcon +"\n" + youtubeIcon);

                // Create a JLabel with StateIcon


                // Create a JComboBox to select states
                String[] states = {"youtube", "google", "xlogistx"};
                JComboBox<String> stateComboBox = new JComboBox<>(states);
                stateComboBox.addActionListener(e -> {
                    String selectedState = (String) stateComboBox.getSelectedItem();
                    stateIcon.setStatus(selectedState);

                });

                // Add components to the frame
                frame.add(stateIcon);
                frame.add(stateComboBox);

                // Make the frame visible
                frame.setVisible(true);
            }
            catch (Exception e)
            {
                e.printStackTrace();
                System.exit(-1);
            }
        });
    }
}
