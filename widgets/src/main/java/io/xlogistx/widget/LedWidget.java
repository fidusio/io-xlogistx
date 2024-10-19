package io.xlogistx.widget;

import org.zoxweb.shared.util.GetName;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

/**
 * LedWidget is a custom Swing component that displays a filled circle (LED)
 * which can be toggled between "on" and "off" states with customizable colors.
 */
public class LedWidget extends JPanel {

    private Color currentColor;
    private final Map<String, Color> colorMap = new HashMap<>();
    /**
     * Constructs a LedWidget with specified dimensions and colors.
     *
     * @param width    The preferred width of the widget.
     * @param height   The preferred height of the widget.
     * @param defaultColor The default color
     */
    public LedWidget(int width, int height, Color defaultColor) {
        // Set preferred size
        this.setPreferredSize(new Dimension(width, height));
        setStatusColor(defaultColor);
    }

    public LedWidget mapColors(Enum<?> tag, Color color)
    {
        colorMap.put(tag.name(), color);
        if(tag instanceof GetName)
        {
            colorMap.put(((GetName) tag).getName(), color);
        }
        return this;
    }

    public LedWidget mapColors(String tag, Color color)
    {
        colorMap.put(tag, color);
        return this;
    }

//    /**
//     * Toggles the LED state between on and off.
//     */
//    public void toggleState() {
//        this.isOn = !this.isOn;
//        repaint(); // Repaint the widget to reflect the state change
//    }

   public boolean setStatus(String status)
   {
       return setStatusColor(getStatusColor(status));
   }

   public boolean setStatus(Enum<?> status)
   {
       return setStatusColor(getStatucColor(status));
   }

   private boolean setStatusColor(Color color)
   {
       if(color != null)
       {
           currentColor = color;
           repaint();
           return true;
       }
       return false;
   }


    public Color getStatucColor(Enum<?> status)
    {
        Color ret = colorMap.get(status.name());
        if (ret == null && status instanceof GetName)
            ret = colorMap.get(((GetName) status).getName());

        return ret;
    }
    public Color getStatusColor(String status)
    {
        return colorMap.get(status);
    }


    /**
     * Overrides the paintComponent method to draw the LED.
     *
     * @param g The Graphics object used for drawing.
     */
    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        drawLED(g);
    }

    /**
     * Draws the LED as a filled circle with the appropriate color based on its state.
     *
     * @param g The Graphics object used for drawing.
     */
    private void drawLED(Graphics g) {
        Graphics2D g2d = (Graphics2D) g.create();

        // Enable anti-aliasing for smooth edges
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);



        // Calculate the largest possible circle within the widget dimensions, considering padding
        int padding = 2;
        int diameter = Math.min(getWidth(), getHeight()) - 2 * padding;
        int x = (getWidth() - diameter) / 2;
        int y = (getHeight() - diameter) / 2;


        // Fill with the off color
        g2d.setColor(currentColor);
        g2d.fillOval(x, y, diameter, diameter);


        // Draw a border around the LED for better visibility
        g2d.setColor(Color.BLACK);
        g2d.setStroke(new BasicStroke(2));
        g2d.drawOval(x, y, diameter, diameter);

        g2d.dispose();
    }
}
