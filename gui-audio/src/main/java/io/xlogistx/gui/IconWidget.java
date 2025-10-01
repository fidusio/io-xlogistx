package io.xlogistx.gui;


import javax.swing.*;
import java.awt.*;

public abstract class IconWidget implements Icon {

    protected final Dimension dimension;
    protected final Color color;
    protected final Color backGroundColor;
    protected IconWidget(int size, Color color, Color backGroundColor)
    {
        this(new Dimension(size, size), color, backGroundColor);
    }

    protected IconWidget(Dimension dimension, Color color, Color backGroundColor)
    {
        this.dimension = dimension;
        this.color = color != null ? color : Color.BLACK;
        this.backGroundColor = backGroundColor != null ? backGroundColor : Color.WHITE;
    }

    /**
     * Returns the icon's width.
     *
     * @return an int specifying the fixed width of the icon.
     */
    @Override
    public int getIconWidth() {
        return dimension.width;
    }

    /**
     * Returns the icon's height.
     *
     * @return an int specifying the fixed height of the icon.
     */
    @Override
    public int getIconHeight() {
        return dimension.height;
    }
}
