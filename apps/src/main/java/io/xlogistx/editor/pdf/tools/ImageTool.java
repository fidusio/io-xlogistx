package io.xlogistx.editor.pdf.tools;

import io.xlogistx.editor.pdf.AddAnnotationEdit;
import io.xlogistx.editor.pdf.AnnotationFactory;
import io.xlogistx.editor.pdf.AnnotationGeometry;
import io.xlogistx.editor.pdf.EditorHost;
import io.xlogistx.editor.pdf.ImageStamp;
import io.xlogistx.gui.pdf.PDFToolContext;
import io.xlogistx.gui.pdf.PDFToolHandler;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.graphics.image.LosslessFactory;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationRubberStamp;
import org.zoxweb.shared.util.SUS;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Cursor;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

/**
 * Places a picture on a page as an image stamp (see
 * {@link io.xlogistx.editor.pdf.ImageStamp}): drag a box (or click) and pick
 * an image file; the picture is fitted into the box keeping its aspect ratio,
 * a click uses the picture's own size (72 dpi, capped to half the page). The
 * placed picture is handed to the selection tool at once, so it can be moved
 * and resized right away (corner handles keep the aspect ratio unless Shift is
 * held); pressing on an existing picture with this tool does the same instead
 * of starting a new one.
 */
public final class ImageTool extends EditorTool {

    /** Image file extensions the file chooser offers and PDFBox decodes. */
    public static final String[] EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff"};
    /** A dragged box smaller than this on either side counts as a click. */
    public static final float MIN_SIZE_PT = ShapeTool.MIN_SIZE_PT;
    /** Margin kept from the page edges when the default placement is shifted onto the page, in points. */
    public static final float MARGIN_PT = 12f;

    private int page = -1;
    private Point2D.Float start;
    private Rectangle2D.Float band;
    private File lastDirectory;

    public ImageTool(EditorHost host) {
        super(host);
    }

    @Override
    public String getName() {
        return "Image";
    }

    @Override
    public void cancel(PDFToolContext c) {
        int p = page;
        page = -1;
        start = null;
        band = null;
        if (p >= 0)
            c.repaintPage(p);
    }

    @Override
    public void pressed(PDFToolContext c, MouseEvent e) {
        page = c.pageAt(e.getPoint());
        start = page < 0 ? null : c.toPagePt(page, e.getPoint());
        band = null;
        if (page < 0)
            return;
        // an existing picture under the pointer: grab it with the selection tool instead
        PageTransform t = transformOf(c, page);
        PDAnnotation hit = t == null ? null : AnnotationGeometry.hitTest(annotationsOf(c, page), t, start, 0f);
        if (hit != null && ImageStamp.isImage(hit)) {
            int p = page;
            page = -1;
            start = null;
            host.selectWithTool(p, hit);
            PDFToolHandler now = host.viewer().getCustomTool();
            if (now != null && now != this)
                now.pressed(c, e); // the drag goes on as a move / resize
        }
    }

    @Override
    public void dragged(PDFToolContext c, MouseEvent e) {
        if (start == null)
            return;
        band = ShapeTool.rect(start, c.toPagePt(page, e.getPoint()));
        c.repaintPage(page);
    }

    @Override
    public void released(PDFToolContext c, MouseEvent e) {
        int p = page;
        Point2D.Float s = start;
        Rectangle2D.Float r = band;
        cancel(c);
        if (p < 0 || s == null)
            return;
        if (r != null && (r.width < MIN_SIZE_PT || r.height < MIN_SIZE_PT))
            r = null;
        File file = chooseFile();
        if (file == null)
            return;
        PDAnnotationRubberStamp a = addImage(c, p, r == null ? new Rectangle2D.Float(s.x, s.y, 0, 0) : r, file);
        if (a != null)
            host.selectWithTool(p, a);
    }

    /** Opens the image file chooser. @return the chosen file, null when cancelled or headless */
    public File chooseFile() {
        if (GraphicsEnvironment.isHeadless())
            return null;
        JFileChooser chooser = new JFileChooser(lastDirectory);
        chooser.setDialogTitle("Insert image");
        chooser.setFileFilter(new FileNameExtensionFilter("Images (png, jpg, gif, bmp, tiff)", EXTENSIONS));
        chooser.setAcceptAllFileFilterUsed(true);
        if (chooser.showOpenDialog(host.dialogParent()) != JFileChooser.APPROVE_OPTION)
            return null;
        File f = chooser.getSelectedFile();
        if (f != null)
            lastDirectory = f.getParentFile();
        return f;
    }

    /**
     * Adds an image file as a stamp (undoable). JPEG data is embedded as is,
     * other formats losslessly.
     *
     * @param page     zero-based page
     * @param viewRect where the picture goes in view space: the picture is
     *                 fitted into it keeping its aspect ratio; a rectangle
     *                 without size (or null) places the picture at its own size
     *                 at that corner (the page's top-left margin when null)
     * @param file     the image file
     * @return the stamp, null when the page is gone or the file could not be read (an error is shown)
     */
    public PDAnnotationRubberStamp addImage(PDFToolContext c, int page, Rectangle2D viewRect, File file) {
        SUS.checkIfNull("file null", file);
        PDImageXObject image;
        synchronized (c.docLock()) {
            PDDocument doc = c.document();
            if (doc == null)
                return null;
            try {
                image = PDImageXObject.createFromFileByContent(file, doc);
            } catch (IOException | RuntimeException e) {
                c.showError("Cannot read the image " + file.getName() + ": " + e.getMessage());
                return null;
            }
        }
        return add(c, page, viewRect, image);
    }

    /**
     * Adds a picture as a stamp (undoable), embedded losslessly.
     *
     * @param viewRect see {@link #addImage(PDFToolContext, int, Rectangle2D, File)}
     * @return the stamp, null when the page is gone
     */
    public PDAnnotationRubberStamp addImage(PDFToolContext c, int page, Rectangle2D viewRect, BufferedImage picture) {
        SUS.checkIfNull("picture null", picture);
        PDImageXObject image;
        synchronized (c.docLock()) {
            PDDocument doc = c.document();
            if (doc == null)
                return null;
            try {
                image = LosslessFactory.createFromImage(doc, picture);
            } catch (IOException e) {
                c.showError("Cannot embed the picture: " + e.getMessage());
                return null;
            }
        }
        return add(c, page, viewRect, image);
    }

    private PDAnnotationRubberStamp add(PDFToolContext c, int page, Rectangle2D viewRect, PDImageXObject image) {
        PDAnnotationRubberStamp a;
        synchronized (c.docLock()) {
            PDPage pg = pageOf(c, page);
            if (pg == null)
                return null;
            PageTransform t = PageTransform.of(pg);
            Rectangle2D.Float box = placement(image.getWidth(), image.getHeight(), viewRect, t.widthPt(), t.heightPt());
            try {
                a = AnnotationFactory.image(c.document(), pg, t, box, image, host.style(EditorHost.StyleKey.IMAGE));
            } catch (IOException e) {
                c.showError("Cannot draw the image: " + e.getMessage());
                return null;
            }
        }
        return apply(c, new AddAnnotationEdit(c.panel(), page, a)) ? a : null;
    }

    /**
     * Where a picture of {@code imgW} x {@code imgH} pixels lands.
     *
     * @param viewRect the requested box in view space; fitted into (keeping the
     *                 aspect ratio, anchored at its top-left corner) when it has
     *                 a size, else its corner is used with the picture's own size
     *                 in points (72 dpi) capped to half the page; null = the
     *                 page's top-left margin
     * @param pageW    page width in points (view space)
     * @param pageH    page height in points
     * @return the box, shifted to stay on the page when the natural size is used
     */
    public static Rectangle2D.Float placement(int imgW, int imgH, Rectangle2D viewRect, float pageW, float pageH) {
        float aspect = imgW > 0 && imgH > 0 ? imgW / (float) imgH : 1f;
        if (viewRect != null && viewRect.getWidth() >= MIN_SIZE_PT && viewRect.getHeight() >= MIN_SIZE_PT) {
            float w = (float) viewRect.getWidth(), h = w / aspect;
            if (h > viewRect.getHeight()) {
                h = (float) viewRect.getHeight();
                w = h * aspect;
            }
            return new Rectangle2D.Float((float) viewRect.getX(), (float) viewRect.getY(), w, h);
        }
        float x = viewRect == null ? MARGIN_PT : (float) viewRect.getX();
        float y = viewRect == null ? MARGIN_PT : (float) viewRect.getY();
        float w = imgW > 0 ? imgW : 100f, h = imgH > 0 ? imgH : 100f;
        float maxW = Math.max(MIN_SIZE_PT, pageW / 2), maxH = Math.max(MIN_SIZE_PT, pageH / 2);
        if (w > maxW) {
            w = maxW;
            h = w / aspect;
        }
        if (h > maxH) {
            h = maxH;
            w = h * aspect;
        }
        if (x + w > pageW - MARGIN_PT)
            x = Math.max(0f, pageW - MARGIN_PT - w);
        if (y + h > pageH - MARGIN_PT)
            y = Math.max(0f, pageH - MARGIN_PT - h);
        return new Rectangle2D.Float(x, y, w, h);
    }

    @Override
    public void paintOverlay(PDFToolContext c, int pageIndex, Graphics2D g2) {
        if (pageIndex != page || band == null)
            return;
        float z = c.zoom();
        prepare(g2, new java.awt.Color(30, 110, 220), 1f, z, true);
        g2.draw(new Rectangle2D.Float(band.x * z, band.y * z, band.width * z, band.height * z));
    }

    @Override
    public Cursor cursor() {
        return Cursor.getPredefinedCursor(Cursor.CROSSHAIR_CURSOR);
    }

    @Override
    public boolean followsLinks() {
        return false;
    }
}
