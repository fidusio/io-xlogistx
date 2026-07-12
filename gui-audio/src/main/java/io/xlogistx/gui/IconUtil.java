package io.xlogistx.gui;

import com.github.weisj.jsvg.SVGDocument;
import com.github.weisj.jsvg.attributes.ViewBox;
import com.github.weisj.jsvg.parser.SVGLoader;
import io.xlogistx.common.util.NVColor;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Icon library for the io.xlogistx GUI components.
 * <p>
 * Provides:
 * <ul>
 *   <li>Vector-drawn action icons ({@link PlusIcon}, {@link MinusIcon}, {@link SaveIcon},
 *       {@link CancelIcon}, {@link UpdateIcon})</li>
 *   <li>SVG-based icons ({@link EditIcon}, {@link DeleteIcon}, {@link SVGIcon}) and the
 *       {@link #svgIcon(String, int)} / {@link #svgIcon(String, int, Color)} factories</li>
 *   <li>Look-and-feel icon shortcuts ({@link #plusIcon()}, {@link #minusIcon()})</li>
 * </ul>
 * To wrap any of these in a button use {@link GUIUtil#iconButton(Icon, boolean)}.
 * All members are static; the class is not instantiable.
 */
public class IconUtil {

    /** Parsed SVG documents cached per resource URL; safe to share across icons. */
    private static final Map<String, SVGDocument> SVG_DOC_CACHE = new ConcurrentHashMap<>();

    private IconUtil() {
    }

    /**
     * Returns the look-and-feel provided tree "expanded" icon, usually rendered as a
     * minus box. Resolved lazily so it reflects the look-and-feel active at call time.
     *
     * @return the icon, or null if the current look-and-feel does not define it
     */
    public static Icon minusIcon() {
        return UIManager.getIcon("Tree.expandedIcon");
    }

    /**
     * Returns the look-and-feel provided tree "collapsed" icon, usually rendered as a
     * plus box. Resolved lazily so it reflects the look-and-feel active at call time.
     *
     * @return the icon, or null if the current look-and-feel does not define it
     */
    public static Icon plusIcon() {
        return UIManager.getIcon("Tree.collapsedIcon");
    }

    /**
     * Vector-drawn plus (+) icon, typically used for "add" buttons.
     * Defaults to a white glyph on a dark green background.
     */
    public static class PlusIcon extends IconWidget {

        /**
         * Creates a square plus icon with a white glyph.
         *
         * @param size icon width and height in pixels
         */
        public PlusIcon(int size) {
            this(size, Color.WHITE);
        }

        /**
         * Creates a square plus icon.
         *
         * @param size  icon width and height in pixels
         * @param color glyph color
         */
        public PlusIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue());
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int w = getIconWidth();
            int h = getIconHeight();
            c.setBackground(backGroundColor);
            g2.setColor(color);
            int thickness = Math.max(2, w / 8);

            // vertical line
            g2.fillRect(x + w / 2 - thickness / 2, y + 4, thickness, h - 8);
            // horizontal line
            g2.fillRect(x + 4, y + h / 2 - thickness / 2, w - 8, thickness);

            g2.dispose();
        }

    }


    /**
     * Vector-drawn check-mark icon, typically used for "save"/"confirm" buttons.
     * Defaults to a white glyph on a dark green background.
     */
    public static class SaveIcon extends IconWidget {

        /**
         * Creates a square save (check-mark) icon with a white glyph.
         *
         * @param size icon width and height in pixels
         */
        public SaveIcon(int size) {
            this(size, Color.WHITE);
        }

        /**
         * Creates a square save (check-mark) icon.
         *
         * @param size  icon width and height in pixels
         * @param color glyph color
         */
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

    /**
     * Vector-drawn X (cross) icon, typically used for "cancel"/"close" buttons.
     * Defaults to a white glyph on a red background.
     */
    public static class CancelIcon extends IconWidget {

        /**
         * Creates a square cancel (X) icon with a white glyph.
         *
         * @param size icon width and height in pixels
         */
        public CancelIcon(int size) {
            this(size, Color.WHITE);
        }

        /**
         * Creates a square cancel (X) icon.
         *
         * @param size  icon width and height in pixels
         * @param color glyph color
         */
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

    /**
     * Vector-drawn minus (-) icon, typically used for "remove"/"delete" buttons.
     * Defaults to a white glyph on a red background.
     */
    public static class MinusIcon extends IconWidget {

        /**
         * Creates a square minus icon with a white glyph.
         *
         * @param size icon width and height in pixels
         */
        public MinusIcon(int size) {
            this(size, Color.WHITE);
        }

        /**
         * Creates a square minus icon.
         *
         * @param size  icon width and height in pixels
         * @param color glyph color
         */
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
            int thickness = Math.max(2, w / 8);

            // horizontal line
            g2.fillRect(x + 4, y + h / 2 - thickness / 2, w - 8, thickness);

            g2.dispose();
        }
    }

    /**
     * Vector-drawn circular-arrow (refresh) icon, typically used for "update" buttons.
     * Defaults to a white glyph on a blue background. Two rendering variants are
     * provided; {@link #paintIcon(Component, Graphics, int, int)} delegates to
     * {@link #halfCirclePaintIcon(Component, Graphics, int, int)}.
     */
    public static class UpdateIcon extends IconWidget {

        /**
         * Creates a square update (refresh) icon with a white glyph.
         *
         * @param size icon width and height in pixels
         */
        public UpdateIcon(int size) {
            this(size, Color.WHITE);
        }

        /**
         * Creates a square update (refresh) icon.
         *
         * @param size  icon width and height in pixels
         * @param color glyph color
         */
        public UpdateIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue());
        }


        /**
         * Alternative rendering: a 270-degree arc with an arrowhead, padded further
         * from the icon edge than {@link #halfCirclePaintIcon(Component, Graphics, int, int)}.
         *
         * @param c component used for background painting
         * @param g graphics context to draw into
         * @param x left coordinate of the icon
         * @param y top coordinate of the icon
         */
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

        /**
         * Default rendering: a 270-degree arc with an arrowhead close to the icon edge.
         *
         * @param c component used for background painting
         * @param g graphics context to draw into
         * @param x left coordinate of the icon
         * @param y top coordinate of the icon
         */
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


    /**
     * Pencil (edit) icon rendered from the bundled {@code pencil.svg} classpath resource,
     * tinted with the requested color. Defaults to a white glyph on a blue background.
     */
    public static class EditIcon extends IconWidget {

        private final SVGIcon svg;

        /**
         * Creates a square edit (pencil) icon with a white glyph.
         *
         * @param size icon width and height in pixels
         */
        public EditIcon(int size) {
            this(size, Color.WHITE);
        }

        /**
         * Creates a square edit (pencil) icon.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public EditIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue());
            svg = svgIcon("io/xlogistx/gui/icons/pencil.svg", size, this.color);
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            c.setBackground(backGroundColor);
            svg.paintIcon(c, g, x, y);
        }

    }

    /**
     * Trash-can (delete) icon rendered from the bundled {@code trash.svg} classpath
     * resource, tinted with the requested color. Defaults to a white glyph on a red background.
     */
    public static class DeleteIcon extends IconWidget {

        private final SVGIcon svg;

        /**
         * Creates a square delete (trash-can) icon with a white glyph.
         *
         * @param size icon width and height in pixels
         */
        public DeleteIcon(int size) {
            this(size, Color.WHITE);
        }

        /**
         * Creates a square delete (trash-can) icon.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public DeleteIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_RED.getValue());
            svg = svgIcon("io/xlogistx/gui/icons/trash.svg", size, this.color);
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            c.setBackground(backGroundColor);
            svg.paintIcon(c, g, x, y);
        }

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
        // raster cache: re-rendered only when the device scale changes (accessed on the EDT only)
        private BufferedImage cachedImage;
        private double cachedScale = -1;

        /**
         * Loads an SVG document from the given URL (parsed documents are cached and
         * shared between icons of the same resource).
         *
         * @param url  location of the svg document
         * @param size icon width and height in pixels
         * @param tint color applied to the whole glyph, null to keep the svg's own colors
         * @throws IllegalArgumentException if the url is null or the document cannot be parsed
         */
        public SVGIcon(URL url, int size, Color tint) {

            if (url == null)
                throw new IllegalArgumentException("svg url is null");
            document = SVG_DOC_CACHE.computeIfAbsent(url.toString(), k -> new SVGLoader().load(url));
            this.dimension = new Dimension(size, size);
            this.tint = tint;
            if (document == null)
                throw new IllegalArgumentException("invalid svg resource: " + url);
        }


        /**
         * Loads an SVG document from a classpath resource.
         *
         * @param resource classpath resource path of the svg file (e.g. "io/xlogistx/gui/icons/pencil.svg")
         * @param size     icon width and height in pixels
         * @param tint     color applied to the whole glyph, null to keep the svg's own colors
         * @throws IllegalArgumentException if the resource is not found or cannot be parsed
         */
        public SVGIcon(String resource, int size, Color tint) {
            this(resourceURL(resource), size, tint);
        }

        /**
         * Resolves a classpath resource, failing with the resource name in the message
         * (the URL constructor can no longer report it once the lookup returned null).
         *
         * @param resource classpath resource path of the svg file
         * @return the resource URL, never null
         * @throws IllegalArgumentException if the resource is not on the classpath
         */
        private static URL resourceURL(String resource) {
            URL url = IconUtil.class.getClassLoader().getResource(resource);
            if (url == null)
                throw new IllegalArgumentException("svg resource not found: " + resource);
            return url;
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

            if (cachedImage == null || cachedScale != scale) {
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
                cachedImage = image;
                cachedScale = scale;
            }

            g2.drawImage(cachedImage, x, y, w, h, null);
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
     * @param resource classpath resource path of the svg file (e.g. "io/xlogistx/gui/icons/pencil.svg")
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
}
