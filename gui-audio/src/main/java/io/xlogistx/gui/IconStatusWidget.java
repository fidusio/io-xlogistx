package io.xlogistx.gui;

import javax.swing.*;
import java.awt.*;

/**
 * IconStatusWidget is a custom Swing component that displays an icon representing
 * different states. Icons can be mapped to various status strings or enums via
 * {@link StatusWidget#mapStatus(String, Object)} and switched with
 * {@link StatusWidget#setStatus(String)}.
 * <p>
 * Mapped icons must be {@link ImageIcon} instances (enforced by the type parameter);
 * the current icon is scaled through {@link ImageIcon#getImage()}.
 */
public class IconStatusWidget extends StatusWidget<ImageIcon> {

    /**
     * Constructs an IconStatusWidget with the specified preferred dimensions.
     *
     * @param width  The preferred width of the widget.
     * @param height The preferred height of the widget.
     */
    public IconStatusWidget(int width, int height) {
        // Set preferred size
        this.setPreferredSize(new Dimension(width, height));
    }


    /**
     * Overrides the paintComponent method to draw the current icon.
     *
     * @param g The Graphics object used for drawing.
     */
    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        drawIcon(g);
    }

    /**
     * Draws the current icon scaled to fit within the widget dimensions, maintaining aspect ratio.
     *
     * @param g The Graphics object used for drawing.
     */
    private void drawIcon(Graphics g) {
        if (currentValue == null) {
            return; // No icon to display
        }

        Graphics2D g2d = (Graphics2D) g.create();

        // Enable anti-aliasing for smooth rendering
        g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);

        // Calculate scaling to maintain aspect ratio
        int padding = 5;
        int availableWidth = getWidth() - 2 * padding;
        int availableHeight = getHeight() - 2 * padding;

        int iconWidth = currentValue.getIconWidth();
        int iconHeight = currentValue.getIconHeight();
        if (iconWidth <= 0 || iconHeight <= 0) {
            g2d.dispose();
            return; // image failed to load
        }

        double widthRatio = (double) availableWidth / iconWidth;
        double heightRatio = (double) availableHeight / iconHeight;
        double scale = Math.min(widthRatio, heightRatio);

        int scaledWidth = (int) (iconWidth * scale);
        int scaledHeight = (int) (iconHeight * scale);

        // Calculate position to center the icon
        int x = (getWidth() - scaledWidth) / 2;
        int y = (getHeight() - scaledHeight) / 2;

        // Draw the scaled icon
        g2d.drawImage(currentValue.getImage(), x, y, scaledWidth, scaledHeight, this);

        g2d.dispose();
    }
}
