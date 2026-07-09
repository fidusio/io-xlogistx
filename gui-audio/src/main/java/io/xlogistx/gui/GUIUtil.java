package io.xlogistx.gui;

import io.xlogistx.common.util.NVColor;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import java.awt.*;
import com.github.weisj.jsvg.SVGDocument;
import com.github.weisj.jsvg.attributes.ViewBox;
import com.github.weisj.jsvg.parser.SVGLoader;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.net.URL;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class GUIUtil {



    public static final String ADD_SIGN = "+";// "\u2795";
    public static final String DELETE_SIGN = "-";//"\u2796";
    public static final String UPDATE_SIGN = "\uD83D\uDD04";


    public static final Icon MINUS_ICON = UIManager.getIcon("Tree.expandedIcon");   // usually a minus box
    public static final Icon PLUS_ICON = UIManager.getIcon("Tree.collapsedIcon"); // usually a plus box

    public static class PlusIcon extends IconWidget {


        public PlusIcon(int size) {
            this(size, Color.WHITE);
        }

        public PlusIcon(int size, Color color) {
            super(size, color, NVColor.DARK_GREEN.getValue());
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int w = getIconWidth();
            int h = getIconHeight();
            c.setBackground(backGroundColor);
            g2.setColor(color);
            int thickness = 2;

            // vertical line
            g2.fillRect(x + w / 2 - thickness / 2, y + 4, thickness, h - 8);
            // horizontal line
            g2.fillRect(x + 4, y + h / 2 - thickness / 2, w - 8, thickness);

            g2.dispose();
        }

    }


    public static class SaveIcon extends IconWidget {


        public SaveIcon(int size) {
            this(size, Color.WHITE);
        }

        public SaveIcon(int size, Color color) {
            super(size, color, NVColor.DARK_GREEN.getValue());
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setStroke(new BasicStroke(Math.max(2, dimension.height / 6), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            c.setBackground(backGroundColor);
            g2.setColor(color);

            int w = getIconWidth();
            int h = getIconHeight();

            // Draw check mark: left bottom → middle → top right
            int x1 = x + w / 6;
            int y1 = y + h / 2;
            int x2 = x + w / 2;
            int y2 = y + h - h / 4;
            int x3 = x + w - w / 6;
            int y3 = y + h / 4;

            g2.drawLine(x1, y1, x2, y2);
            g2.drawLine(x2, y2, x3, y3);

            g2.dispose();
        }

    }

    public static class CancelIcon extends IconWidget {


        public CancelIcon(int size) {
            this(size, Color.WHITE);
        }

        public CancelIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_RED.color());
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setStroke(new BasicStroke(Math.max(2, dimension.width / 6), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            c.setBackground(backGroundColor);
            g2.setColor(color);

            int w = getIconWidth();
            int h = getIconHeight();

            g2.drawLine(x + 4, y + 4, x + w - 4, y + h - 4);
            g2.drawLine(x + w - 4, y + 4, x + 4, y + h - 4);

            g2.dispose();
        }

    }

    public static class MinusIcon extends IconWidget {


        public MinusIcon(int size) {
            this(size, Color.WHITE);
        }

        public MinusIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_RED.getValue());
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int w = getIconWidth();
            int h = getIconHeight();
            c.setBackground(backGroundColor);
            g2.setColor(color);
            int thickness = 2;

            // horizontal line
            g2.fillRect(x + 4, y + h / 2 - thickness / 2, w - 8, thickness);

            g2.dispose();
        }
    }

    public static class UpdateIcon extends IconWidget {


        public UpdateIcon(int size) {
            this(size, Color.WHITE);
        }

        public UpdateIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue());
        }


        public void circlePaintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setStroke(new BasicStroke(Math.max(2, dimension.width / 10), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.setColor(color);
            c.setBackground(backGroundColor);

            int w = getIconWidth();
            int h = getIconHeight();
            int pad = dimension.width / 6;

            // Draw arc (almost a circle)
            g2.drawArc(x + pad, y + pad, w - 2 * pad, h - 2 * pad, 45, 270);

            // Draw arrowhead at the end of arc
            int arrowSize = dimension.width / 4;
            Polygon arrowHead = new Polygon();
            int cx = x + w - pad;         // arrow tip X
            int cy = y + h / 2;           // arrow tip Y

            arrowHead.addPoint(cx, cy);                             // tip
            arrowHead.addPoint(cx - arrowSize, cy - arrowSize / 2); // back top
            arrowHead.addPoint(cx - arrowSize, cy + arrowSize / 2); // back bottom

            g2.fill(arrowHead);

            g2.dispose();
        }

        public void halfCirclePaintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int w = getIconWidth();
            int h = getIconHeight();
            int strokeWidth = Math.max(2, dimension.width / 10);

            g2.setStroke(new BasicStroke(strokeWidth, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));

            c.setBackground(backGroundColor);

            g2.setColor(color);

            // Draw circular arc
            int pad = strokeWidth;
            g2.drawArc(x + pad, y + pad, w - 2 * pad, h - 2 * pad, 30, 270);

            // Draw arrowhead at the end of arc
            int arrowSize = dimension.width / 4;
            Polygon arrowHead = new Polygon();
            arrowHead.addPoint(x + w - pad - arrowSize, y + h / 2);        // left
            arrowHead.addPoint(x + w - pad, y + h / 2 - arrowSize / 2);    // top
            arrowHead.addPoint(x + w - pad, y + h / 2 + arrowSize / 2);    // bottom
            g2.fillPolygon(arrowHead);

            g2.dispose();
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            halfCirclePaintIcon(c, g, x, y);
        }

    }


    public static class EditIcon extends IconWidget {

        private final SVGIcon svg;

        public EditIcon(int size) {
            this(size, Color.WHITE);
        }

        public EditIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue());
            svg = svgIcon("io/xlogistx/gui/icons/edit.svg", size, this.color);
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            c.setBackground(backGroundColor);
            svg.paintIcon(c, g, x, y);
        }

    }

    public static class DeleteIcon extends IconWidget {

        private final SVGIcon svg;

        public DeleteIcon(int size) {
            this(size, Color.WHITE);
        }

        public DeleteIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_RED.getValue());
            svg = svgIcon("io/xlogistx/gui/icons/delete.svg", size, this.color);
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            c.setBackground(backGroundColor);
            svg.paintIcon(c, g, x, y);
        }

    }


    private static final Lock lock = new ReentrantLock();

    private static final Clipboard systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard();

    private GUIUtil() {
    }

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
    public static BufferedImage captureSelectedArea(Rectangle area) throws AWTException {
        Robot robot = new Robot();
        return robot.createScreenCapture(area);
    }

    public static Rectangle captureSelectedArea()
            throws AWTException, InterruptedException {
        Condition cond = lock.newCondition();
        SelectionWindow selectionWindow = new SelectionWindow(lock, cond);
        selectionWindow.setVisible(true);
        selectionWindow.toFront();

        try {
            lock.lock();
            cond.await();
        } finally {
            lock.unlock();
        }

        selectionWindow.dispose();

        // Get the selected area
        return selectionWindow.getSelectedArea();
    }


    public static void copyToClipboard(String text) {
        copyToClipboard(systemClipboard, text);
    }


    public static void copyToClipboard(Clipboard clipboard, String text) {
        // Create a StringSelection with the desired text
        StringSelection stringSelection = new StringSelection(text);
        // Set the clipboard contents to the StringSelection
        clipboard.setContents(stringSelection, null); // null for owner means no owner
    }

    public static JPanel createPanel(String title, LayoutManager layout, JComponent... components) {
        JPanel panel = new JPanel(layout);
        for (JComponent component : components)
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
    public static JScrollPane createScrollPane(JComponent jComponent, String title, Font titleFont, Dimension dimension) {
        JScrollPane scrollPane = new JScrollPane(jComponent);
        TitledBorder border = BorderFactory.createTitledBorder(title);
        border.setTitleFont(titleFont != null ? titleFont : new Font("SansSerif", Font.BOLD, 12));
        scrollPane.setBorder(border);
        if (dimension != null) {
            scrollPane.setPreferredSize(dimension);
        }

        return scrollPane;
    }

    public static Color colorToRation(Color start, Color mid, Color end, float ratio) {
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


    public static Color colorToRation(float ratio) {
        return colorToRation(NVColor.START_COLOR.color(), NVColor.MID_COLOR.color(), NVColor.END_COLOR.color(), ratio);
    }

    public static Color interpolateColors(Color start, Color end, float ratio) {
        int r = (int) (start.getRed() + (end.getRed() - start.getRed()) * ratio);
        int g = (int) (start.getGreen() + (end.getGreen() - start.getGreen()) * ratio);
        int b = (int) (start.getBlue() + (end.getBlue() - start.getBlue()) * ratio);
        return new Color(r, g, b);
    }


    /**
     * Icon rendered from an SVG document via JSVG, scaled to the requested size.
     * The vector is rasterized at the actual device scale (HiDPI aware) and can
     * optionally be tinted with a single color while preserving the glyph alpha.
     */
    public static class SVGIcon implements Icon {

        private final SVGDocument document;
        private final Dimension dimension;
        private final Color tint;

        public SVGIcon(String resource, int size, Color tint) {
            this.dimension = new Dimension(size, size);
            this.tint = tint;
            URL url = GUIUtil.class.getClassLoader().getResource(resource);
            if (url == null)
                throw new IllegalArgumentException("svg resource not found: " + resource);
            document = new SVGLoader().load(url);
            if (document == null)
                throw new IllegalArgumentException("invalid svg resource: " + resource);
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            int w = getIconWidth();
            int h = getIconHeight();

            // rasterize at the device scale so the icon stays sharp on HiDPI displays
            AffineTransform transform = g2.getTransform();
            double scale = Math.max(transform.getScaleX(), transform.getScaleY());
            if (scale <= 0)
                scale = 1;
            int pw = (int) Math.ceil(w * scale);
            int ph = (int) Math.ceil(h * scale);

            BufferedImage image = new BufferedImage(pw, ph, BufferedImage.TYPE_INT_ARGB);
            Graphics2D ig = image.createGraphics();
            ig.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            document.render(c instanceof JComponent ? (JComponent) c : null, ig, new ViewBox(0, 0, pw, ph));
            if (tint != null) {
                // keep the glyph alpha, replace its color
                ig.setComposite(AlphaComposite.SrcIn);
                ig.setColor(tint);
                ig.fillRect(0, 0, pw, ph);
            }
            ig.dispose();

            g2.drawImage(image, x, y, w, h, null);
            g2.dispose();
        }

        @Override
        public int getIconWidth() {
            return dimension.width;
        }

        @Override
        public int getIconHeight() {
            return dimension.height;
        }
    }

    /**
     * Loads an SVG icon from the classpath scaled to the given size.
     *
     * @param resource classpath resource path of the svg file (e.g. "io/xlogistx/gui/icons/edit.svg")
     * @param size     icon width and height in pixels
     * @return the svg icon
     */
    public static SVGIcon svgIcon(String resource, int size) {
        return svgIcon(resource, size, null);
    }

    /**
     * Loads an SVG icon from the classpath scaled to the given size and recolored.
     *
     * @param resource classpath resource path of the svg file
     * @param size     icon width and height in pixels
     * @param color    color applied to the whole glyph, null to keep the svg colors
     * @return the svg icon
     */
    public static SVGIcon svgIcon(String resource, int size, Color color) {
        return new SVGIcon(resource, size, color);
    }


    public static JButton iconButton(Icon icon) {
        JButton ret = new JButton(icon);
        Dimension dimension = new Dimension(icon.getIconWidth(), icon.getIconHeight());
        ret.setPreferredSize(dimension);
        ret.setMaximumSize(dimension);
        return ret;

    }
}
