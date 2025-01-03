package io.xlogistx.widget;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.image.BufferedImage;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class WidgetUtil {
    private static final Lock lock = new ReentrantLock();

    private static final Clipboard systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
    private WidgetUtil(){}

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
}
