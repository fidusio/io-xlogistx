package io.xlogistx.gui;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.image.BufferedImage;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class GUIUtil {
    public static final Color START_COLOR = new Color(255, 0, 0);    // Red
    public static final Color MID_COLOR   = new Color(0, 128, 255);  // Blueish
    public static final Color END_COLOR   = new Color(0, 255, 0);

    public static final String ADD_SIGN = "+";// "\u2795";
    public static final String DELETE_SIGN = "-";//"\u2796";
    public static final String UPDATE_SIGN = "\uD83D\uDD04";


    public static final Icon MINUS_ICON  = UIManager.getIcon("Tree.expandedIcon");   // usually a minus box
    public static final Icon PLUS_ICON = UIManager.getIcon("Tree.collapsedIcon"); // usually a plus box

    public static class PlusIcon implements Icon {
        private final int size;

        public PlusIcon(int size) {
            this.size = size;
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int w = getIconWidth();
            int h = getIconHeight();
            g2.setColor(Color.BLACK);
            int thickness = 2;

            // vertical line
            g2.fillRect(x + w / 2 - thickness / 2, y + 4, thickness, h - 8);
            // horizontal line
            g2.fillRect(x + 4, y + h / 2 - thickness / 2, w - 8, thickness);

            g2.dispose();
        }

        @Override public int getIconWidth() { return size; }
        @Override public int getIconHeight() { return size; }
    }

    public static class MinusIcon implements Icon {
        private final int size;

        public MinusIcon(int size) {
            this.size = size;
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int w = getIconWidth();
            int h = getIconHeight();
            g2.setColor(Color.BLACK);
            int thickness = 2;

            // horizontal line
            g2.fillRect(x + 4, y + h / 2 - thickness / 2, w - 8, thickness);

            g2.dispose();
        }

        @Override public int getIconWidth() { return size; }
        @Override public int getIconHeight() { return size; }
    }

    public static class UpdateIcon implements Icon {
        private final int size;
        private final Color color;

        public UpdateIcon(int size, Color color) {
            this.size = size;
            this.color = color;
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int w = getIconWidth();
            int h = getIconHeight();
            int strokeWidth = Math.max(2, size / 10);

            g2.setStroke(new BasicStroke(strokeWidth, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.setColor(color);

            // Draw circular arc
            int pad = strokeWidth;
            g2.drawArc(x + pad, y + pad, w - 2 * pad, h - 2 * pad, 30, 270);

            // Draw arrowhead at the end of arc
            int arrowSize = size / 4;
            Polygon arrowHead = new Polygon();
            arrowHead.addPoint(x + w - pad - arrowSize, y + h / 2);        // left
            arrowHead.addPoint(x + w - pad, y + h / 2 - arrowSize / 2);    // top
            arrowHead.addPoint(x + w - pad, y + h / 2 + arrowSize / 2);    // bottom
            g2.fillPolygon(arrowHead);

            g2.dispose();
        }

        @Override public int getIconWidth()  { return size; }
        @Override public int getIconHeight() { return size; }
    }


    private static final Lock lock = new ReentrantLock();

    private static final Clipboard systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
    private GUIUtil(){}

    public static boolean compareImages(BufferedImage imgA, BufferedImage imgB) {
        // Check if dimensions are the same
        if (imgA == null || imgB == null ||
                imgA.getWidth() != imgB.getWidth() ||
                imgA.getHeight() != imgB.getHeight()) {
            return false;
        }

        int width = imgA.getWidth();
        int height = imgA.getHeight();

        // Compare pixel by pixel
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                // Get the RGB values of the pixels
                int pixelA = imgA.getRGB(x, y);
                int pixelB = imgB.getRGB(x, y);

                if (pixelA != pixelB) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Capture a rectangular area from the screen
     * @param area to be captured
     * @return imge of the area
     * @throws AWTException in case of error
     */
    public static BufferedImage captureSelectedArea(Rectangle area) throws AWTException
    {
        Robot robot = new Robot();
        return robot.createScreenCapture(area);
    }

    public  static Rectangle captureSelectedArea()
            throws AWTException, InterruptedException
    {
        Condition cond = lock.newCondition();
        SelectionWindow selectionWindow = new SelectionWindow(lock, cond);
        selectionWindow.setVisible(true);
        selectionWindow.toFront();

        try
        {
            lock.lock();
            cond.await();
        }
        finally
        {
            lock.unlock();
        }

        selectionWindow.dispose();

        // Get the selected area
        return selectionWindow.getSelectedArea();
    }


    public static void copyToClipboard(String text)
    {
        copyToClipboard(systemClipboard, text);
    }


    public static void copyToClipboard(Clipboard clipboard, String text) {
        // Create a StringSelection with the desired text
        StringSelection stringSelection = new StringSelection(text);
        // Set the clipboard contents to the StringSelection
        clipboard.setContents(stringSelection, null); // null for owner means no owner
    }

    public static JPanel createPanel(String title, LayoutManager layout, JComponent ...components)
    {
        JPanel panel = new JPanel(layout);
        for (JComponent component: components)
            panel.add(component);

        // Optionally, set a border with the panel title
        panel.setBorder(BorderFactory.createTitledBorder(title));

        return panel;
    }

    /**
     * Configures a JTextArea with default settings.
     *
     * @param textArea The JTextArea to configure.
     * @param font     of the text area, null a default one will be created.
     * @param border of the text area, null a default one will be created.
     * @return The updated text aread
     */
    public static JTextArea configureTextArea(JTextArea textArea, Font font, Border border) {
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setFont(font != null ? font : new Font("SansSerif", Font.PLAIN, 14));
        textArea.setBorder(border != null ? border : BorderFactory.createEmptyBorder(5, 5, 5, 5));
        return textArea;
    }
    /**
     * Creates a JScrollPane containing the given JTextArea with a titled border.
     *
     * @param jComponent The JComponent to include in the scroll pane.
     * @param title    The title for the border.
     * @param titleFont if null a default on will be created
     * @param dimension preferred size of the scroll pane null is ok
     * @return A JScrollPane containing the text area.
     */
    public static  JScrollPane createScrollPane(JComponent jComponent, String title, Font titleFont, Dimension dimension) {
        JScrollPane scrollPane = new JScrollPane(jComponent);
        TitledBorder border = BorderFactory.createTitledBorder(title);
        border.setTitleFont(titleFont != null ? titleFont : new Font("SansSerif", Font.BOLD, 12));
        scrollPane.setBorder(border);
        if(dimension != null)
        {
            scrollPane.setPreferredSize(dimension);
        }

        return scrollPane;
    }

    public static Color colorToRation(Color start, Color mid, Color end, float ratio)
    {
        if (ratio <= 0.5f) {
            // Interpolate from Red (t=0) to Blueish (t=0.5)
            ratio = ratio / 0.5f; // Maps [0..0.5] -> [0..1]
            return interpolateColors(start, mid, ratio);
        } else {
            // Interpolate from Blueish (t=0.5) to Green (t=1.0)
            ratio = (ratio - 0.5f) / 0.5f; // Maps [0.5..1] -> [0..1]
            return interpolateColors(mid, end, ratio);
        }
    }


    public static Color colorToRation(float ratio)
    {
        return colorToRation(START_COLOR, MID_COLOR, END_COLOR, ratio);
    }

    public static Color interpolateColors(Color start, Color end, float ratio)
    {
        int r = (int) (start.getRed() + (end.getRed() - start.getRed()) * ratio);
        int g = (int) (start.getGreen() + (end.getGreen() - start.getGreen()) * ratio);
        int b = (int) (start.getBlue() + (end.getBlue() - start.getBlue()) * ratio);
        return new Color(r, g, b);
    }
}
