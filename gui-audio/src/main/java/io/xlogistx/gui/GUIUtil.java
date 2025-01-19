package io.xlogistx.gui;

import javax.swing.*;
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
