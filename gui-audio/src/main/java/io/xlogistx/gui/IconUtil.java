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
 *   <li>SVG-based icons ({@link PlusIcon}, {@link MinusIcon}, {@link CancelIcon},
 *       {@link SaveIcon}, {@link UpdateIcon}, {@link EditIcon}, {@link DeleteIcon},
 *       {@link BackIcon}, {@link NextIcon}, {@link RollbackIcon}, {@link VisibleIcon},
 *       {@link InvisibleIcon}, {@link CopyIcon}, {@link SearchIcon}, {@link RefreshIcon},
 *       {@link SVGIcon}) and the
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
     * Plus (+) icon rendered from the bundled {@code plus.svg} classpath resource,
     * typically used for "add" buttons.
     */
    public static class PlusIcon extends SVGIconWidget {

        /**
         * Creates a square plus icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public PlusIcon(int size) {
            super(size, "io/xlogistx/gui/icons/plus.svg");
        }

        /**
         * Creates a square plus icon tinted with the given color on a blue background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public PlusIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue(), "io/xlogistx/gui/icons/plus.svg");
        }
    }


    /**
     * Base class for the SVG-backed icons. The single-int constructors render the svg
     * with its own colors and leave the hosting component's background untouched; the
     * tinted constructors recolor the glyph and paint the icon's background color on
     * the hosting component.
     */
    public static abstract class SVGIconWidget extends IconWidget {

        /** The rendered svg icon. */
        protected final SVGIcon svg;
        /** True when the svg's own colors are used (no tint, no background override). */
        protected final boolean svgDefaults;

        /**
         * Creates a square icon rendered with the svg's own colors.
         *
         * @param size     icon width and height in pixels
         * @param resource classpath resource path of the svg file
         */
        protected SVGIconWidget(int size, String resource) {
            super(size, (Color) null, (Color) null);
            svgDefaults = true;
            svg = svgIcon(resource, size);
        }

        /**
         * Creates a square icon with a tinted glyph and a background color applied to
         * the hosting component while painting.
         *
         * @param size            icon width and height in pixels
         * @param color           glyph tint color
         * @param backGroundColor background color applied to the hosting component
         * @param resource        classpath resource path of the svg file
         */
        protected SVGIconWidget(int size, Color color, Color backGroundColor, String resource) {
            super(size, color, backGroundColor);
            svgDefaults = false;
            svg = svgIcon(resource, size, this.color);
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            if (!svgDefaults)
                c.setBackground(backGroundColor);
            svg.paintIcon(c, g, x, y);
        }
    }

    /**
     * Save (floppy-disk) icon rendered from the bundled {@code save.svg} classpath resource.
     */
    public static class SaveIcon extends SVGIconWidget {

        /**
         * Creates a square save icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public SaveIcon(int size) {
            super(size, "io/xlogistx/gui/icons/save.svg");
        }

        /**
         * Creates a square save icon tinted with the given color on a dark green background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public SaveIcon(int size, Color color) {
            super(size, color, NVColor.DARK_GREEN.getValue(), "io/xlogistx/gui/icons/save.svg");
        }
    }

    /**
     * Cancel (X cross) icon rendered from the bundled {@code cancel.svg} classpath
     * resource, typically used for "cancel"/"close" buttons.
     */
    public static class CancelIcon extends SVGIconWidget {

        /**
         * Creates a square cancel (X) icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public CancelIcon(int size) {
            super(size, "io/xlogistx/gui/icons/cancel.svg");
        }

        /**
         * Creates a square cancel (X) icon tinted with the given color on a red background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public CancelIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_RED.getValue(), "io/xlogistx/gui/icons/cancel.svg");
        }
    }

    /**
     * Minus (-) icon rendered from the bundled {@code minus.svg} classpath resource,
     * typically used for "remove" buttons.
     */
    public static class MinusIcon extends SVGIconWidget {

        /**
         * Creates a square minus icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public MinusIcon(int size) {
            super(size, "io/xlogistx/gui/icons/minus.svg");
        }

        /**
         * Creates a square minus icon tinted with the given color on a red background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public MinusIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_RED.getValue(), "io/xlogistx/gui/icons/minus.svg");
        }
    }

    /**
     * Update (two chasing arrows / sync) icon rendered from the bundled
     * {@code update.svg} classpath resource.
     */
    public static class UpdateIcon extends SVGIconWidget {

        /**
         * Creates a square update (two chasing arrows) icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public UpdateIcon(int size) {
            super(size, "io/xlogistx/gui/icons/update.svg");
        }

        /**
         * Creates a square update (two chasing arrows) icon tinted with the given color
         * on a blue background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public UpdateIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue(), "io/xlogistx/gui/icons/update.svg");
        }
    }


    /**
     * Pencil (edit) icon rendered from the bundled {@code edit.svg} classpath resource.
     */
    public static class EditIcon extends SVGIconWidget {

        /**
         * Creates a square edit (pencil) icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public EditIcon(int size) {
            super(size, "io/xlogistx/gui/icons/edit.svg");
        }

        /**
         * Creates a square edit (pencil) icon tinted with the given color on a blue background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public EditIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue(), "io/xlogistx/gui/icons/edit.svg");
        }
    }

    /**
     * Trash-can (delete) icon rendered from the bundled {@code delete.svg} classpath resource.
     */
    public static class DeleteIcon extends SVGIconWidget {

        /**
         * Creates a square delete (trash-can) icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public DeleteIcon(int size) {
            super(size, "io/xlogistx/gui/icons/delete.svg");
        }

        /**
         * Creates a square delete (trash-can) icon tinted with the given color on a red background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public DeleteIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_RED.getValue(), "io/xlogistx/gui/icons/delete.svg");
        }
    }

    /**
     * Back (left arrow) icon rendered from the bundled {@code back.svg} classpath resource.
     */
    public static class BackIcon extends SVGIconWidget {

        /**
         * Creates a square back (left arrow) icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public BackIcon(int size) {
            super(size, "io/xlogistx/gui/icons/back.svg");
        }

        /**
         * Creates a square back (left arrow) icon tinted with the given color on a blue background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public BackIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue(), "io/xlogistx/gui/icons/back.svg");
        }
    }

    /**
     * Next (right arrow) icon rendered from the bundled {@code next.svg} classpath resource.
     */
    public static class NextIcon extends SVGIconWidget {

        /**
         * Creates a square next (right arrow) icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public NextIcon(int size) {
            super(size, "io/xlogistx/gui/icons/next.svg");
        }

        /**
         * Creates a square next (right arrow) icon tinted with the given color on a blue background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public NextIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue(), "io/xlogistx/gui/icons/next.svg");
        }
    }

    /**
     * Rollback (counterclockwise circular arrow) icon rendered from the bundled
     * {@code rollback.svg} classpath resource.
     */
    public static class RollbackIcon extends SVGIconWidget {

        /**
         * Creates a square rollback icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public RollbackIcon(int size) {
            super(size, "io/xlogistx/gui/icons/rollback.svg");
        }

        /**
         * Creates a square rollback icon tinted with the given color on an orange background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public RollbackIcon(int size, Color color) {
            super(size, color, NVColor.ORANGE.getValue(), "io/xlogistx/gui/icons/rollback.svg");
        }
    }

    /**
     * Visible (open eye) icon rendered from the bundled {@code visible.svg} classpath resource.
     */
    public static class VisibleIcon extends SVGIconWidget {

        /**
         * Creates a square visible (open eye) icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public VisibleIcon(int size) {
            super(size, "io/xlogistx/gui/icons/visible.svg");
        }

        /**
         * Creates a square visible (open eye) icon tinted with the given color on a green background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public VisibleIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_GREEN.getValue(), "io/xlogistx/gui/icons/visible.svg");
        }
    }

    /**
     * Invisible (crossed-out eye) icon rendered from the bundled {@code invisible.svg}
     * classpath resource.
     */
    public static class InvisibleIcon extends SVGIconWidget {

        /**
         * Creates a square invisible (crossed-out eye) icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public InvisibleIcon(int size) {
            super(size, "io/xlogistx/gui/icons/invisible.svg");
        }

        /**
         * Creates a square invisible (crossed-out eye) icon tinted with the given color
         * on a grey background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public InvisibleIcon(int size, Color color) {
            super(size, color, NVColor.GREY.getValue(), "io/xlogistx/gui/icons/invisible.svg");
        }
    }


    /**
     * Copy (duplicate pages) icon rendered from the bundled {@code copy.svg} classpath resource.
     */
    public static class CopyIcon extends SVGIconWidget {

        /**
         * Creates a square copy icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public CopyIcon(int size) {
            super(size, "io/xlogistx/gui/icons/copy.svg");
        }

        /**
         * Creates a square copy icon tinted with the given color on a blue background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public CopyIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue(), "io/xlogistx/gui/icons/copy.svg");
        }
    }

    /**
     * Search (magnifying glass) icon rendered from the bundled {@code search.svg}
     * classpath resource.
     */
    public static class SearchIcon extends SVGIconWidget {

        /**
         * Creates a square search (magnifying glass) icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public SearchIcon(int size) {
            super(size, "io/xlogistx/gui/icons/search.svg");
        }

        /**
         * Creates a square search (magnifying glass) icon tinted with the given color
         * on a blue background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public SearchIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue(), "io/xlogistx/gui/icons/search.svg");
        }
    }


    /**
     * Refresh (circular arrows) icon rendered from the bundled {@code refresh.svg}
     * classpath resource.
     */
    public static class RefreshIcon extends SVGIconWidget {

        /**
         * Creates a square refresh (circular arrows) icon rendered with the svg's own colors.
         *
         * @param size icon width and height in pixels
         */
        public RefreshIcon(int size) {
            super(size, "io/xlogistx/gui/icons/refresh.svg");
        }

        /**
         * Creates a square refresh (circular arrows) icon tinted with the given color
         * on a blue background.
         *
         * @param size  icon width and height in pixels
         * @param color glyph tint color
         */
        public RefreshIcon(int size, Color color) {
            super(size, color, NVColor.BOOTSTRAP_BLUE.getValue(), "io/xlogistx/gui/icons/refresh.svg");
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
