package io.xlogistx.gui;


import io.xlogistx.common.util.NVColor;
import org.zoxweb.server.util.ServerUtil;

import javax.swing.*;
import java.awt.*;

/**
 * Base class for fixed-size, programmatically painted icons (see the concrete
 * implementations in {@link IconUtil}: PlusIcon, MinusIcon, SaveIcon, CancelIcon,
 * UpdateIcon, EditIcon, DeleteIcon).
 * <p>
 * Holds the icon dimension, the glyph color and the background color applied to the
 * hosting component. On macOS the glyph and background colors are swapped because
 * Swing buttons there do not honor the background color the same way.
 */
public abstract class IconWidget implements Icon {

    /** Fixed width and height of the icon. */
    protected final Dimension dimension;
    /** Color used to paint the glyph. */
    protected final Color color;
    /** Background color applied to the hosting component while painting. */
    protected final Color backGroundColor;

    /**
     * Creates a square icon.
     *
     * @param size            icon width and height in pixels
     * @param color           glyph color, null defaults to black (white on macOS)
     * @param backGroundColor background color, null defaults to white (black on macOS)
     */
    protected IconWidget(int size, Color color, Color backGroundColor) {
        this(new Dimension(size, size), color, backGroundColor);
    }

    /**
     * Creates an icon with the given dimension.
     *
     * @param dimension       icon width and height
     * @param color           glyph color, null defaults to black (white on macOS)
     * @param backGroundColor background color, null defaults to white (black on macOS)
     */
    protected IconWidget(Dimension dimension, Color color, Color backGroundColor) {
        this.dimension = dimension;

        // If the System is a Mac, paint the + or - and not the background (doing it the other way does not work)
        // If the System isn't a Mac paint the background and leave interior white
        Color fg = color != null ? color : Color.BLACK;
        Color bg = backGroundColor != null ? backGroundColor : Color.WHITE;
        if (ServerUtil.isMacOS()) {
            this.color = bg;
            this.backGroundColor = fg;
        } else {
            this.color = fg;
            this.backGroundColor = bg;
        }
    }

    /**
     * Creates a square icon from {@link NVColor} values.
     *
     * @param size            icon width and height in pixels
     * @param color           glyph color, null defaults to black (white on macOS)
     * @param backGroundColor background color, null defaults to white (black on macOS)
     */
    protected IconWidget(int size, NVColor color, NVColor backGroundColor) {
        this(new Dimension(size, size), color != null ? color.getValue() : null, backGroundColor != null ? backGroundColor.color() : null);
    }

    /**
     * Creates an icon with the given dimension from {@link NVColor} values.
     *
     * @param dimension       icon width and height
     * @param color           glyph color, null defaults to black (white on macOS)
     * @param backGroundColor background color, null defaults to white (black on macOS)
     */
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
