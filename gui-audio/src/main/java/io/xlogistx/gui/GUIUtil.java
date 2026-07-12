package io.xlogistx.gui;

import io.xlogistx.common.util.NVColor;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.image.BufferedImage;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Static Swing helper library for the io.xlogistx GUI components.
 * <p>
 * Provides:
 * <ul>
 *   <li>Icon button factories ({@link #iconButton(Icon)} and overloads); the icons
 *       themselves live in {@link IconUtil}</li>
 *   <li>Screen capture utilities ({@link #captureSelectedArea()} and
 *       {@link #captureSelectedArea(Rectangle)})</li>
 *   <li>Clipboard, panel/scroll-pane creation and color interpolation helpers</li>
 * </ul>
 * All members are static; the class is not instantiable.
 */
public class GUIUtil {


    /** Textual plus sign usable as a button label for "add" actions. */
    public static final String ADD_SIGN = "+";// "➕";
    /** Textual minus sign usable as a button label for "delete" actions. */
    public static final String DELETE_SIGN = "-";//"➖";
    /** Unicode "counterclockwise arrows" symbol usable as a button label for "update" actions. */
    public static final String UPDATE_SIGN = "🔄";


    private static final Lock lock = new ReentrantLock();

    private GUIUtil() {
    }

    /**
     * Compares two images pixel by pixel.
     *
     * @param imgA first image, may be null
     * @param imgB second image, may be null
     * @return true if both images are non-null, have identical dimensions and every
     *         pixel matches; false otherwise
     */
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
     * Captures a rectangular area of the screen.
     *
     * @param area screen region to be captured
     * @return image of the captured area
     * @throws AWTException if the platform does not allow screen capture
     */
    public static BufferedImage captureSelectedArea(Rectangle area) throws AWTException {
        Robot robot = new Robot();
        return robot.createScreenCapture(area);
    }

    /**
     * Displays a full-screen translucent {@link SelectionWindow} and blocks the calling
     * thread until the user drags out a rectangular selection with the mouse.
     * <p>
     * Must NOT be called on the Event Dispatch Thread since it blocks until the
     * selection is completed.
     *
     * @return the rectangle selected by the user, in screen coordinates
     * @throws AWTException         reserved for screen/toolkit errors
     * @throws InterruptedException if the calling thread is interrupted while waiting
     */
    public static Rectangle captureSelectedArea()
            throws AWTException, InterruptedException {
        if (SwingUtilities.isEventDispatchThread())
            throw new IllegalStateException("captureSelectedArea() must not be called on the EDT");

        Condition cond = lock.newCondition();
        SelectionWindow[] holder = new SelectionWindow[1];
        try {
            // all window realization happens on the EDT; a mouse-released signal firing
            // before await() is harmless because the predicate loop re-checks the state
            SwingUtilities.invokeAndWait(() -> {
                holder[0] = new SelectionWindow(lock, cond);
                holder[0].setVisible(true);
                holder[0].toFront();
            });
        } catch (InvocationTargetException e) {
            throw new AWTException("failed to show selection window: " + e.getCause());
        }
        SelectionWindow selectionWindow = holder[0];

        lock.lock();
        try {
            while (!selectionWindow.isSelectionMade())
                cond.await();
        } finally {
            lock.unlock();
        }

        SwingUtilities.invokeLater(selectionWindow::dispose);

        // Get the selected area
        return selectionWindow.getSelectedArea();
    }


    /**
     * Copies the given text to the system clipboard.
     *
     * @param text text to place on the clipboard
     */
    public static void copyToClipboard(String text) {
        copyToClipboard(Toolkit.getDefaultToolkit().getSystemClipboard(), text);
    }


    /**
     * Copies the given text to the specified clipboard.
     *
     * @param clipboard clipboard to receive the text
     * @param text      text to place on the clipboard
     */
    public static void copyToClipboard(Clipboard clipboard, String text) {
        // Create a StringSelection with the desired text
        StringSelection stringSelection = new StringSelection(text);
        // Set the clipboard contents to the StringSelection
        clipboard.setContents(stringSelection, null); // null for owner means no owner
    }

    /**
     * Creates a JPanel with the given layout, adds the supplied components in order
     * and decorates it with a titled border.
     *
     * @param title      title of the panel border
     * @param layout     layout manager of the panel
     * @param components components to add to the panel
     * @return the assembled panel
     */
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

    /**
     * Maps a ratio in [0..1] onto a three-color gradient: [0..0.5] interpolates
     * from {@code start} to {@code mid}, and (0.5..1] interpolates from {@code mid}
     * to {@code end}.
     *
     * @param start color at ratio 0
     * @param mid   color at ratio 0.5
     * @param end   color at ratio 1
     * @param ratio position within the gradient, expected in [0..1]
     * @return the interpolated color
     */
    public static Color colorToRatio(Color start, Color mid, Color end, float ratio) {
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


    /**
     * Maps a ratio in [0..1] onto the default three-color gradient defined by
     * {@link NVColor#START_COLOR}, {@link NVColor#MID_COLOR} and {@link NVColor#END_COLOR}.
     *
     * @param ratio position within the gradient, expected in [0..1]
     * @return the interpolated color
     */
    public static Color colorToRatio(float ratio) {
        return colorToRatio(NVColor.START_COLOR.color(), NVColor.MID_COLOR.color(), NVColor.END_COLOR.color(), ratio);
    }

    /**
     * Linearly interpolates each RGB channel between two colors.
     *
     * @param start color at ratio 0
     * @param end   color at ratio 1
     * @param ratio interpolation factor, expected in [0..1]
     * @return the interpolated color
     */
    public static Color interpolateColors(Color start, Color end, float ratio) {
        ratio = Math.max(0f, Math.min(1f, ratio));
        int r = (int) (start.getRed() + (end.getRed() - start.getRed()) * ratio);
        int g = (int) (start.getGreen() + (end.getGreen() - start.getGreen()) * ratio);
        int b = (int) (start.getBlue() + (end.getBlue() - start.getBlue()) * ratio);
        return new Color(r, g, b);
    }


    /**
     * Creates a JButton displaying the given icon with the look-and-feel's default sizing.
     *
     * @param icon icon to display
     * @return the button
     */
    public static JButton iconButton(Icon icon) {
        return iconButton(icon, false);
    }

    /**
     * Creates a JButton displaying the given icon.
     *
     * @param icon             icon to display
     * @param autoSetDimension if true, the button's preferred and maximum size are
     *                         pinned to the icon's dimensions; if false the
     *                         look-and-feel default sizing is kept
     * @return the button
     */
    public static JButton iconButton(Icon icon, boolean autoSetDimension) {
        if(autoSetDimension) {
            return iconButton(icon, new Dimension(icon.getIconWidth(), icon.getIconHeight()));
        }
        return new JButton(icon);
    }

    /**
     * Creates a JButton displaying the given icon, pinned to the given size.
     *
     * @param icon      icon to display
     * @param dimension preferred and maximum size of the button, null to keep the
     *                  look-and-feel default sizing
     * @return the button
     */
    public static JButton iconButton(Icon icon, Dimension dimension) {
        JButton ret = new JButton(icon);
        if(dimension != null) {
            ret.setPreferredSize(dimension);
            ret.setMaximumSize(dimension);
        }
        return ret;
    }
}
