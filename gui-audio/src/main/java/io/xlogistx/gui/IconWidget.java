package io.xlogistx.gui;


import io.xlogistx.common.util.NVColor;
import org.zoxweb.server.util.ServerUtil;

import javax.swing.*;
import java.awt.*;

public abstract class IconWidget implements Icon {

    protected final Dimension dimension;
    protected final Color color;
    protected final Color backGroundColor;

    protected IconWidget(int size, Color color, Color backGroundColor) {
        this(new Dimension(size, size), color, backGroundColor);
    }

    protected IconWidget(Dimension dimension, Color color, Color backGroundColor) {
        this.dimension = dimension;

        // If the System is a Mac, paint the + or - and not the background (doing it the other way does not work)
        // If the System isn't a Mac paint the background and leave interior white
        if (ServerUtil.isMacOS()) {
            this.color = color != null ? backGroundColor : Color.BLACK;
            this.backGroundColor = color != null ? color : Color.WHITE;
        } else {
            this.color = color != null ? color : Color.BLACK;
            this.backGroundColor = backGroundColor != null ? backGroundColor : Color.WHITE;
        }
    }

    protected IconWidget(int size, NVColor color, NVColor backGroundColor) {
        this(new Dimension(size, size), color != null ? color.getValue() : null, backGroundColor != null ? backGroundColor.color() : null);
    }

    protected IconWidget(Dimension dimension, NVColor color, NVColor backGroundColor) {
        this(dimension, color != null ? color.getValue() : null, backGroundColor != null ? backGroundColor.color() : null);
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
