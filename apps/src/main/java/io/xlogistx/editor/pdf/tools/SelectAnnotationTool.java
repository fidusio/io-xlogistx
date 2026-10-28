package io.xlogistx.editor.pdf.tools;

import io.xlogistx.editor.pdf.AddAnnotationEdit;
import io.xlogistx.editor.pdf.AnnotationClipboard;
import io.xlogistx.editor.pdf.AnnotationFactory;
import io.xlogistx.editor.pdf.AnnotationGeometry;
import io.xlogistx.editor.pdf.AnnotationGeometry.Kind;
import io.xlogistx.editor.pdf.AnnotationStyle;
import io.xlogistx.editor.pdf.EditorDialogs;
import io.xlogistx.editor.pdf.EditorHost;
import io.xlogistx.editor.pdf.FreeTextAppearance;
import io.xlogistx.editor.pdf.ImageStamp;
import io.xlogistx.editor.pdf.TextEditor;
import io.xlogistx.editor.pdf.ModifyAnnotationEdit;
import io.xlogistx.editor.pdf.PDFEdit;
import io.xlogistx.editor.pdf.RemoveAnnotationEdit;
import io.xlogistx.gui.pdf.PDFToolContext;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFreeText;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLine;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationMarkup;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationRubberStamp;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationSquareCircle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationText;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDBorderStyleDictionary;
import org.zoxweb.shared.util.SUS;

import javax.swing.JViewport;
import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Graphics2D;
import java.awt.Point;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.awt.geom.Line2D;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.io.IOException;
import java.util.List;

/**
 * Selects, moves, resizes, edits and deletes annotations. A press hit-tests
 * the page (topmost first; popups, links and widgets are skipped); a drag
 * moves the annotation, resizes it by one of eight handles (rectangles,
 * ellipses, text boxes, image stamps; a stamp's corner handles keep the
 * picture's aspect ratio unless Shift is held) or drags a line endpoint, on a working copy of the
 * geometry painted as an overlay while the raster hides the annotation; the
 * release commits one {@link ModifyAnnotationEdit}. Delete removes the
 * selection, a double click edits the text of a note or text box, and
 * {@link #applyStyle} / {@link #editProperties} change colours, opacity,
 * border and font size. A drag that starts on empty space pans the view, so
 * the tool can stay active; hovering shows a move cursor over an annotation
 * and resize cursors over the handles.
 */
public final class SelectAnnotationTool extends EditorTool {

    private static final float HIT_TOLERANCE_PT = 4f;
    private static final int HANDLE_PX = 7;
    private static final float ARROW_ROOM = 10f;

    private enum Drag {
        NONE, MOVE, RESIZE, LINE_START, LINE_END
    }

    private int page = -1;
    private PDAnnotation selected;
    private Drag drag = Drag.NONE;
    private int handle = -1;
    private Point2D.Float pressPt;
    /** Working geometry in view space while dragging. */
    private Rectangle2D.Float workRect;
    private Point2D.Float workP1, workP2;
    private boolean dragging;
    private COSDictionary before;
    /** Where a pan drag is, in viewport coordinates; null when not panning. */
    private Point panOrigin;

    public SelectAnnotationTool(EditorHost host) {
        super(host);
    }

    @Override
    public String getName() {
        return "Select annotation";
    }

    /** @return the selected annotation, null when none */
    public PDAnnotation getSelected() {
        return selected;
    }

    /** @return the selected annotation's page, -1 when none */
    public int getSelectedPage() {
        return selected == null ? -1 : page;
    }

    /** Selects an annotation programmatically (null clears); a text box being typed into is committed first unless it is the one selected. */
    public void select(PDFToolContext c, int page, PDAnnotation a) {
        if (getInPlaceEditor() != null && (a == null || a.getCOSObject() != inPlace.getBox().getCOSObject()))
            commitInPlace();
        int old = this.page;
        this.selected = a;
        this.page = a == null ? -1 : page;
        drag = Drag.NONE;
        dragging = false;
        if (old >= 0)
            c.repaintPage(old);
        if (this.page >= 0)
            c.repaintPage(this.page);
        host.annotationSelected(this.page, a);
    }

    @Override
    public void cancel(PDFToolContext c) {
        if (inPlace != null) {
            InPlaceTextEditor e = inPlace;
            inPlace = null;
            e.cancel(); // Esc, a document change or a page refresh: the typed text is dropped
        }
        if (dragging) {
            c.setAnnotationFilter(null);
            c.invalidatePage(page);
        }
        panOrigin = null;
        drag = Drag.NONE;
        dragging = false;
        workRect = null;
        workP1 = workP2 = null;
        if (page >= 0)
            c.repaintPage(page);
    }

    @Override
    public void deactivated(PDFToolContext c) {
        commitInPlace(); // switching tools keeps what was typed
        super.deactivated(c);
        select(c, -1, null);
    }

    @Override
    public void pressed(PDFToolContext c, MouseEvent e) {
        panOrigin = null;
        int p = c.pageAt(e.getPoint());
        PageTransform t = p < 0 ? null : transformOf(c, p);
        if (t == null) {
            select(c, -1, null);
            startPan(c, e);
            return;
        }
        Point2D.Float pt = c.toPagePt(p, e.getPoint());
        // double click: edit the text of a note / text box
        if (e.getClickCount() == 2 && selected != null && p == page && (selected instanceof PDAnnotationText || selected instanceof PDAnnotationFreeText)) {
            editText(c);
            return;
        }
        // handles of the current selection first
        if (selected != null && p == page) {
            int h = handleAt(c, t, pt);
            if (h >= 0) {
                Kind kind = AnnotationGeometry.kind(selected);
                drag = kind == Kind.LINE ? (h == 0 ? Drag.LINE_START : Drag.LINE_END) : Drag.RESIZE;
                handle = h;
                startDrag(c, t, pt);
                return;
            }
        }
        PDAnnotation hit = AnnotationGeometry.hitTest(annotationsOf(c, p), t, pt, HIT_TOLERANCE_PT);
        if (hit == null) {
            select(c, -1, null);
            startPan(c, e);
            return;
        }
        if (selected == null || hit.getCOSObject() != selected.getCOSObject() || p != page)
            select(c, p, hit);
        drag = Drag.MOVE;
        startDrag(c, t, pt);
    }

    /** A drag on empty space scrolls the view like the pan tool. */
    private void startPan(PDFToolContext c, MouseEvent e) {
        panOrigin = SwingUtilities.convertPoint(c.owner(), e.getPoint(), c.viewport());
        c.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR));
    }

    private void pan(PDFToolContext c, MouseEvent e) {
        JViewport vp = c.viewport();
        Point now = SwingUtilities.convertPoint(c.owner(), e.getPoint(), vp);
        Point pos = vp.getViewPosition();
        int maxX = Math.max(0, c.owner().getWidth() - vp.getWidth());
        int maxY = Math.max(0, c.owner().getHeight() - vp.getHeight());
        pos.x = Math.max(0, Math.min(maxX, pos.x - (now.x - panOrigin.x)));
        pos.y = Math.max(0, Math.min(maxY, pos.y - (now.y - panOrigin.y)));
        vp.setViewPosition(pos);
        panOrigin = now;
    }

    @Override
    public void moved(PDFToolContext c, MouseEvent e) {
        int p = c.pageAt(e.getPoint());
        PageTransform t = p < 0 ? null : transformOf(c, p);
        if (t == null)
            return;
        Point2D.Float pt = c.toPagePt(p, e.getPoint());
        if (selected != null && p == page) {
            int h = handleAt(c, t, pt);
            if (h >= 0) {
                c.setCursor(handleCursor(AnnotationGeometry.kind(selected), h));
                return;
            }
        }
        PDAnnotation hit = AnnotationGeometry.hitTest(annotationsOf(c, p), t, pt, HIT_TOLERANCE_PT);
        c.setCursor(hit != null ? Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR) : cursor());
    }

    /** The resize cursor of a handle (see {@link #handles}: NW, NE, SW, SE, N, S, W, E; lines: crosshair). */
    static Cursor handleCursor(Kind kind, int handle) {
        if (kind == Kind.LINE)
            return Cursor.getPredefinedCursor(Cursor.CROSSHAIR_CURSOR);
        switch (handle) {
            case 0: return Cursor.getPredefinedCursor(Cursor.NW_RESIZE_CURSOR);
            case 1: return Cursor.getPredefinedCursor(Cursor.NE_RESIZE_CURSOR);
            case 2: return Cursor.getPredefinedCursor(Cursor.SW_RESIZE_CURSOR);
            case 3: return Cursor.getPredefinedCursor(Cursor.SE_RESIZE_CURSOR);
            case 4: return Cursor.getPredefinedCursor(Cursor.N_RESIZE_CURSOR);
            case 5: return Cursor.getPredefinedCursor(Cursor.S_RESIZE_CURSOR);
            case 6: return Cursor.getPredefinedCursor(Cursor.W_RESIZE_CURSOR);
            case 7: return Cursor.getPredefinedCursor(Cursor.E_RESIZE_CURSOR);
            default: return Cursor.getDefaultCursor();
        }
    }

    private void startDrag(PDFToolContext c, PageTransform t, Point2D.Float pt) {
        pressPt = pt;
        dragging = false;
        synchronized (c.docLock()) {
            before = ModifyAnnotationEdit.snapshot(selected);
            workRect = AnnotationGeometry.bounds(selected, t);
            if (selected instanceof PDAnnotationLine) {
                float[] l = ((PDAnnotationLine) selected).getLine();
                if (l != null && l.length >= 4) {
                    workP1 = t.toView(new Point2D.Float(l[0], l[1]));
                    workP2 = t.toView(new Point2D.Float(l[2], l[3]));
                }
            }
        }
    }

    @Override
    public void dragged(PDFToolContext c, MouseEvent e) {
        if (panOrigin != null) {
            pan(c, e);
            return;
        }
        if (drag == Drag.NONE || selected == null || pressPt == null)
            return;
        Point2D.Float pt = c.toPagePt(page, e.getPoint());
        if (!dragging) {
            if (pt.distance(pressPt) * c.zoom() < 2)
                return;
            dragging = true;
            final COSDictionary hidden = selected.getCOSObject();
            c.setAnnotationFilter(a -> a.getCOSObject() != hidden);
            c.invalidatePage(page);
        }
        float dx = pt.x - pressPt.x, dy = pt.y - pressPt.y;
        PageTransform t = transformOf(c, page);
        if (t == null)
            return;
        Rectangle2D.Float base = AnnotationGeometry.bounds(selected, t);
        switch (drag) {
            case MOVE:
                workRect = new Rectangle2D.Float(base.x + dx, base.y + dy, base.width, base.height);
                if (workP1 != null) {
                    float[] l = ((PDAnnotationLine) selected).getLine();
                    Point2D.Float p1 = t.toView(new Point2D.Float(l[0], l[1])), p2 = t.toView(new Point2D.Float(l[2], l[3]));
                    workP1 = new Point2D.Float(p1.x + dx, p1.y + dy);
                    workP2 = new Point2D.Float(p2.x + dx, p2.y + dy);
                }
                break;
            case RESIZE:
                workRect = handle < 4 && !e.isShiftDown() && selected instanceof PDAnnotationRubberStamp
                        ? resizedKeepingAspect(base, handle, dx, dy)
                        : resized(base, handle, dx, dy);
                break;
            case LINE_START:
            case LINE_END: {
                float[] l = ((PDAnnotationLine) selected).getLine();
                Point2D.Float p1 = t.toView(new Point2D.Float(l[0], l[1])), p2 = t.toView(new Point2D.Float(l[2], l[3]));
                if (drag == Drag.LINE_START)
                    p1 = new Point2D.Float(p1.x + dx, p1.y + dy);
                else
                    p2 = new Point2D.Float(p2.x + dx, p2.y + dy);
                workP1 = p1;
                workP2 = p2;
                workRect = ShapeTool.rect(p1, p2);
                break;
            }
            default:
                break;
        }
        c.repaintPage(page);
    }

    @Override
    public void released(PDFToolContext c, MouseEvent e) {
        if (panOrigin != null) {
            panOrigin = null;
            c.setCursor(cursor());
            return;
        }
        if (drag == Drag.NONE || selected == null) {
            drag = Drag.NONE;
            return;
        }
        Drag d = drag;
        boolean moved = dragging;
        drag = Drag.NONE;
        dragging = false;
        if (!moved) {
            workRect = null;
            c.repaintPage(page);
            return;
        }
        PageTransform t = transformOf(c, page);
        c.setAnnotationFilter(null);
        if (t == null) {
            c.invalidatePage(page);
            return;
        }
        String name;
        synchronized (c.docLock()) {
            switch (d) {
                case MOVE: {
                    Point2D.Float from = t.toPdf(pressPt);
                    Point2D.Float to = t.toPdf(new Point2D.Float(pressPt.x + (workRect.x - AnnotationGeometry.bounds(selected, t).x),
                            pressPt.y + (workRect.y - AnnotationGeometry.bounds(selected, t).y)));
                    AnnotationGeometry.translate(selected, to.x - from.x, to.y - from.y);
                    name = "Move " + label();
                    break;
                }
                case RESIZE:
                    AnnotationGeometry.setBounds(selected, t.toPdfRect(workRect));
                    name = "Resize " + label();
                    break;
                default: {
                    Point2D.Float a = t.toPdf(workP1), b = t.toPdf(workP2);
                    PDBorderStyleDictionary bs = ((PDAnnotationLine) selected).getBorderStyle();
                    float room = (bs == null ? 1f : bs.getWidth()) + ARROW_ROOM;
                    AnnotationGeometry.setLine((PDAnnotationLine) selected, a.x, a.y, b.x, b.y, room);
                    name = "Change line";
                }
            }
        }
        workRect = null;
        workP1 = workP2 = null;
        commit(c, name);
    }

    /** Commits the annotation's current state against {@link #before} as one edit, or just re-renders when nothing changed. */
    private void commit(PDFToolContext c, String name) {
        COSDictionary after;
        synchronized (c.docLock()) {
            after = ModifyAnnotationEdit.snapshot(selected);
        }
        if (before != null && ModifyAnnotationEdit.differs(before, after))
            apply(c, new ModifyAnnotationEdit(c.panel(), page, selected, before, after, name));
        else
            c.invalidatePage(page);
        before = null;
        host.annotationSelected(page, selected);
    }

    @Override
    public void keyPressed(PDFToolContext c, KeyEvent e) {
        if (e.getKeyCode() == KeyEvent.VK_DELETE || e.getKeyCode() == KeyEvent.VK_BACK_SPACE) {
            deleteSelected(c);
            return;
        }
        if (selected == null)
            return; // arrows scroll the view as usual
        float step = e.isShiftDown() ? NUDGE_BIG_PT : NUDGE_PT;
        float dx = 0, dy = 0;
        switch (e.getKeyCode()) {
            case KeyEvent.VK_LEFT: dx = -step; break;
            case KeyEvent.VK_RIGHT: dx = step; break;
            case KeyEvent.VK_UP: dy = -step; break;
            case KeyEvent.VK_DOWN: dy = step; break;
            default: return;
        }
        e.consume(); // keeps the scroll pane from scrolling
        nudgeSelected(c, dx, dy);
    }

    /** Points an arrow key moves the selection by; with Shift {@link #NUDGE_BIG_PT}. */
    public static final float NUDGE_PT = 1f, NUDGE_BIG_PT = 10f;
    /** Nudges closer together than this many ms merge into one undo step. */
    public static final long NUDGE_BURST_MS = 600;
    private ModifyAnnotationEdit lastNudge;
    private long lastNudgeAt;

    /**
     * Moves the selection by a small view-space delta (arrow keys): a burst of
     * nudges closer together than {@link #NUDGE_BURST_MS} is one undo step, as
     * long as nothing else was done in between.
     *
     * @param dxPt points to the right
     * @param dyPt points down
     * @return true when moved
     */
    public boolean nudgeSelected(PDFToolContext c, float dxPt, float dyPt) {
        if (selected == null)
            return false;
        long now = System.currentTimeMillis();
        boolean merge = lastNudge != null && host.model().peekUndo() == lastNudge && now - lastNudgeAt < NUDGE_BURST_MS
                && lastNudge.getAnnotation().getCOSObject() == selected.getCOSObject();
        lastNudgeAt = now;
        if (!merge) {
            if (!moveSelected(c, dxPt, dyPt))
                return false;
            PDFEdit top = host.model().peekUndo();
            lastNudge = top instanceof ModifyAnnotationEdit && ((ModifyAnnotationEdit) top).getAnnotation() == selected ? (ModifyAnnotationEdit) top : null;
            return true;
        }
        PageTransform t = transformOf(c, page);
        if (t == null)
            return false;
        synchronized (c.docLock()) {
            Point2D.Float from = t.toPdf(new Point2D.Float(0, 0)), to = t.toPdf(new Point2D.Float(dxPt, dyPt));
            AnnotationGeometry.translate(selected, to.x - from.x, to.y - from.y);
            AnnotationFactory.rebuildAppearance(c.document(), selected);
            lastNudge.amend(ModifyAnnotationEdit.snapshot(selected));
        }
        c.invalidatePage(page);
        host.annotationSelected(page, selected);
        return true;
    }

    /**
     * The editable annotation under a point of the pages panel (topmost first;
     * popups, links and widgets are skipped), without selecting it.
     *
     * @param panelPoint a point in pages-panel coordinates (a mouse event's point)
     * @return the page index and the annotation, null when none is there
     */
    public Hit annotationAt(PDFToolContext c, Point panelPoint) {
        int p = c.pageAt(panelPoint);
        PageTransform t = p < 0 ? null : transformOf(c, p);
        if (t == null)
            return null;
        PDAnnotation a = AnnotationGeometry.hitTest(annotationsOf(c, p), t, c.toPagePt(p, panelPoint), HIT_TOLERANCE_PT);
        return a == null ? null : new Hit(p, a);
    }

    /** An annotation found under a point: its page and itself. */
    public static final class Hit {
        public final int page;
        public final PDAnnotation annotation;

        Hit(int page, PDAnnotation annotation) {
            this.page = page;
            this.annotation = annotation;
        }
    }

    /** Removes the selected annotation (undoable). @return true when one was removed */
    public boolean deleteSelected(PDFToolContext c) {
        return deleteSelected(c, "Delete");
    }

    /**
     * Removes the selected annotation (undoable).
     *
     * @param verb what the undo history calls it: "Delete", "Cut"
     * @return true when one was removed
     */
    public boolean deleteSelected(PDFToolContext c, String verb) {
        if (selected == null)
            return false;
        PDAnnotation a = selected;
        int p = page;
        select(c, -1, null);
        return apply(c, new RemoveAnnotationEdit(c.panel(), p, a, verb));
    }

    // ------------------------------------------------------------------ copy / paste

    /** How far a duplicate sits right and below its original, in points. */
    public static final float DUPLICATE_OFFSET_PT = 10f;

    /** @return a clip of the selection for the clipboard, null when nothing is selected */
    public AnnotationClipboard.Clip copySelected(PDFToolContext c) {
        if (selected == null)
            return null;
        synchronized (c.docLock()) {
            PDDocument doc = c.document();
            return doc == null ? null : AnnotationClipboard.copy(doc, selected);
        }
    }

    /**
     * Pastes a clip on a page as a new annotation (undoable), its box centred
     * on a point and kept on the page, and selects it.
     *
     * @param clip       the clip, never null
     * @param page       zero-based page
     * @param viewCentre where the middle of the box goes, in view space (points, top-left origin of the page)
     * @param verb       what the undo history calls it: "Paste", "Duplicate"
     * @return the new annotation, null when the page is gone or the clip cannot be rebuilt (an error is shown)
     */
    public PDAnnotation paste(PDFToolContext c, AnnotationClipboard.Clip clip, int page, Point2D viewCentre, String verb) {
        SUS.checkIfNull("clip null", clip);
        SUS.checkIfNull("centre null", viewCentre);
        PageTransform t = transformOf(c, page);
        if (t == null)
            return null;
        PDAnnotation a;
        synchronized (c.docLock()) {
            PDPage pg = pageOf(c, page);
            if (pg == null)
                return null;
            PDRectangle r = t.toPdfRect(placed(clip.width(), clip.height(), viewCentre, t.widthPt(), t.heightPt()));
            try {
                a = clip.create(c.document(), pg, Math.min(r.getLowerLeftX(), r.getUpperRightX()), Math.min(r.getLowerLeftY(), r.getUpperRightY()));
            } catch (IOException | RuntimeException e) {
                c.showError("Cannot paste the " + clip.kind() + ": " + e.getMessage());
                return null;
            }
        }
        if (!apply(c, new AddAnnotationEdit(c.panel(), page, a, (verb == null ? "Paste" : verb) + " " + labelOf(a))))
            return null;
        select(c, page, a);
        return a;
    }

    /**
     * Adds a copy of the selection {@link #DUPLICATE_OFFSET_PT} right and below
     * it (undoable) and selects the copy.
     *
     * @return the copy, null when nothing is selected
     */
    public PDAnnotation duplicateSelected(PDFToolContext c) {
        AnnotationClipboard.Clip clip = copySelected(c);
        if (clip == null)
            return null;
        PageTransform t = transformOf(c, page);
        if (t == null)
            return null;
        Rectangle2D.Float b;
        synchronized (c.docLock()) {
            b = AnnotationGeometry.bounds(selected, t);
        }
        return paste(c, clip, page, new Point2D.Float(b.x + b.width / 2 + DUPLICATE_OFFSET_PT, b.y + b.height / 2 + DUPLICATE_OFFSET_PT), "Duplicate");
    }

    /** A {@code w} x {@code h} box centred on a point, moved to stay on a {@code pageW} x {@code pageH} page where it fits. */
    static Rectangle2D.Float placed(float w, float h, Point2D centre, float pageW, float pageH) {
        float x = (float) centre.getX() - w / 2, y = (float) centre.getY() - h / 2;
        x = Math.max(0f, Math.min(x, pageW - w));
        y = Math.max(0f, Math.min(y, pageH - h));
        return new Rectangle2D.Float(x, y, w, h);
    }

    /**
     * Edits the text of the selection: a text box is typed into on the page
     * ({@link #editInPlace}), a note through the text dialog.
     *
     * @return true when the in-place editor opened, or the dialog changed the note
     */
    public boolean editText(PDFToolContext c) {
        if (selected instanceof PDAnnotationFreeText)
            return editInPlace(c);
        if (!(selected instanceof PDAnnotationText))
            return false;
        String current = selected.getContents();
        String text = EditorDialogs.askText(host.dialogParent(), "Edit text", current == null ? "" : current, true);
        if (text == null || text.equals(current))
            return false;
        return setContents(c, text);
    }

    // ------------------------------------------------------------------ in-place text

    private InPlaceTextEditor inPlace;

    /**
     * Starts typing into the selected text box on the page (see
     * {@link InPlaceTextEditor}); committing with a changed text is one "Edit
     * text" undo step, the box stays selected.
     *
     * @return true when the editor is open (already or now), false when no text box is selected
     */
    public boolean editInPlace(PDFToolContext c) {
        if (!(selected instanceof PDAnnotationFreeText))
            return false;
        if (getInPlaceEditor() != null)
            return true;
        PageTransform t = transformOf(c, page);
        if (t == null)
            return false;
        final PDAnnotationFreeText box = (PDAnnotationFreeText) selected;
        final int p = page;
        Rectangle2D.Float r;
        String original;
        synchronized (c.docLock()) {
            r = AnnotationGeometry.bounds(box, t);
            original = box.getContents() == null ? "" : box.getContents();
        }
        inPlace = new InPlaceTextEditor(c, p, box, r, true, text -> {
            inPlace = null;
            if (!text.equals(original))
                commitText(c, p, box, text);
        }, () -> inPlace = null);
        inPlace.show();
        return true;
    }

    private void commitText(PDFToolContext c, int p, PDAnnotationFreeText box, String text) {
        COSDictionary before, after;
        synchronized (c.docLock()) {
            before = ModifyAnnotationEdit.snapshot(box);
            box.setContents(text);
            AnnotationFactory.rebuildAppearance(c.document(), box);
            after = ModifyAnnotationEdit.snapshot(box);
        }
        apply(c, new ModifyAnnotationEdit(c.panel(), p, box, before, after, "Edit text"));
        if (selected != null && selected.getCOSObject() == box.getCOSObject())
            host.annotationSelected(p, box);
    }

    /** @return the in-place editor while one is open, else null */
    public InPlaceTextEditor getInPlaceEditor() {
        return inPlace != null && inPlace.isActive() ? inPlace : null;
    }

    /** Commits the in-place edit in progress, if any. @return true when one was committed */
    public boolean commitInPlace() {
        InPlaceTextEditor e = getInPlaceEditor();
        if (e == null)
            return false;
        e.commit();
        return true;
    }

    /** Sets the selected annotation's text (undoable). */
    public boolean setContents(PDFToolContext c, String text) {
        if (selected == null)
            return false;
        synchronized (c.docLock()) {
            before = ModifyAnnotationEdit.snapshot(selected);
            selected.setContents(text);
            AnnotationFactory.rebuildAppearance(c.document(), selected);
        }
        commit(c, "Edit text");
        return true;
    }

    /** @return the selected annotation's style as far as its dictionary says, null when nothing is selected */
    public AnnotationStyle styleOf(PDFToolContext c) {
        if (selected == null)
            return null;
        synchronized (c.docLock()) {
            Color stroke = AnnotationFactory.awtColor(selected.getColor());
            Color fill = null;
            float opacity = 1f, width = 1f, size = 12f;
            String family = null;
            int fontStyle = java.awt.Font.PLAIN;
            boolean underline = false, strikethrough = false;
            Color highlight = null;
            TextEditor.Alignment alignment = TextEditor.Alignment.LEFT;
            if (selected instanceof PDAnnotationMarkup) {
                PDAnnotationMarkup m = (PDAnnotationMarkup) selected;
                opacity = m.getConstantOpacity();
                PDBorderStyleDictionary bs = m.getBorderStyle();
                if (bs != null)
                    width = bs.getWidth();
            }
            if (selected instanceof PDAnnotationSquareCircle)
                fill = AnnotationFactory.awtColor(((PDAnnotationSquareCircle) selected).getInteriorColor());
            if (selected instanceof PDAnnotationLine)
                fill = AnnotationFactory.awtColor(((PDAnnotationLine) selected).getInteriorColor());
            if (selected instanceof PDAnnotationFreeText) {
                String da = ((PDAnnotationFreeText) selected).getDefaultAppearance();
                fill = stroke;
                stroke = FreeTextAppearance.textColor(da);
                size = FreeTextAppearance.fontSize(da);
                String ds = ((PDAnnotationFreeText) selected).getDefaultStyleString();
                family = FreeTextAppearance.fontFamily(ds);
                fontStyle = FreeTextAppearance.fontStyle(ds);
                underline = FreeTextAppearance.underline(ds);
                strikethrough = FreeTextAppearance.strikethrough(ds);
                highlight = FreeTextAppearance.highlight(ds);
                alignment = FreeTextAppearance.alignment(((PDAnnotationFreeText) selected).getQ());
            }
            if (selected instanceof PDAnnotationRubberStamp)
                return AnnotationStyle.IMAGE.withOpacity(opacity);
            return new AnnotationStyle(stroke == null ? Color.BLACK : stroke, fill, opacity, width, size, family, fontStyle, underline, strikethrough, highlight, alignment, null);
        }
    }

    /** Shows the properties dialog for the selection and applies the result. @return true when changed */
    public boolean editProperties(PDFToolContext c) {
        AnnotationStyle current = styleOf(c);
        if (current == null)
            return false;
        if (selected instanceof PDAnnotationRubberStamp) {
            AnnotationStyle s = EditorDialogs.askImageStyle(host.dialogParent(), current);
            return s != null && applyStyle(c, s);
        }
        boolean withFill = selected instanceof PDAnnotationSquareCircle || selected instanceof PDAnnotationFreeText || selected instanceof PDAnnotationLine;
        AnnotationStyle s = EditorDialogs.askStyle(host.dialogParent(), current, withFill, selected instanceof PDAnnotationFreeText);
        return s != null && applyStyle(c, s);
    }

    /** Applies a style to the selected annotation (undoable). */
    public boolean applyStyle(PDFToolContext c, AnnotationStyle style) {
        if (selected == null)
            return false;
        synchronized (c.docLock()) {
            before = ModifyAnnotationEdit.snapshot(selected);
            if (selected instanceof PDAnnotationFreeText) {
                PDAnnotationFreeText ft = (PDAnnotationFreeText) selected;
                ft.setDefaultAppearance(AnnotationFactory.defaultAppearance(style.getStrokeColor(), style.getFontSize()));
                ft.setDefaultStyleString(FreeTextAppearance.defaultStyle(style));
                ft.setQ(FreeTextAppearance.q(style.getAlignment()));
                if (style.getFillColor() != null)
                    ft.setColor(AnnotationFactory.pdColor(style.getFillColor()));
                else
                    ft.getCOSObject().removeItem(org.apache.pdfbox.cos.COSName.C);
            } else if (!(selected instanceof PDAnnotationRubberStamp))
                selected.setColor(AnnotationFactory.pdColor(style.getStrokeColor()));
            if (selected instanceof PDAnnotationSquareCircle) {
                if (style.getFillColor() != null)
                    ((PDAnnotationSquareCircle) selected).setInteriorColor(AnnotationFactory.pdColor(style.getFillColor()));
                else
                    selected.getCOSObject().removeItem(org.apache.pdfbox.cos.COSName.IC);
            }
            if (selected instanceof PDAnnotationLine) {
                if (style.getFillColor() != null)
                    ((PDAnnotationLine) selected).setInteriorColor(AnnotationFactory.pdColor(style.getFillColor()));
                else
                    selected.getCOSObject().removeItem(org.apache.pdfbox.cos.COSName.IC);
            }
            if (selected instanceof PDAnnotationMarkup) {
                PDAnnotationMarkup m = (PDAnnotationMarkup) selected;
                m.setConstantOpacity(style.getOpacity());
                if (!(selected instanceof PDAnnotationRubberStamp)) {
                    PDBorderStyleDictionary bs = new PDBorderStyleDictionary();
                    bs.setWidth(style.getStrokeWidth());
                    bs.setStyle(PDBorderStyleDictionary.STYLE_SOLID);
                    m.setBorderStyle(bs);
                }
            }
            AnnotationFactory.rebuildAppearance(c.document(), selected);
        }
        commit(c, "Change properties");
        return true;
    }

    @Override
    public void paintOverlay(PDFToolContext c, int pageIndex, Graphics2D g2) {
        if (selected == null || pageIndex != page)
            return;
        PageTransform t = transformOf(c, pageIndex);
        if (t == null)
            return;
        float z = c.zoom();
        Rectangle2D.Float r;
        synchronized (c.docLock()) {
            r = workRect != null ? workRect : AnnotationGeometry.bounds(selected, t);
        }
        Rectangle2D.Float px = new Rectangle2D.Float(r.x * z, r.y * z, r.width * z, r.height * z);
        Kind kind = AnnotationGeometry.kind(selected);
        prepare(g2, new Color(30, 110, 220), 1f, z, true);
        if (kind == Kind.LINE && (workP1 != null || selected instanceof PDAnnotationLine)) {
            Point2D.Float p1 = workP1, p2 = workP2;
            if (p1 == null) {
                float[] l = ((PDAnnotationLine) selected).getLine();
                p1 = t.toView(new Point2D.Float(l[0], l[1]));
                p2 = t.toView(new Point2D.Float(l[2], l[3]));
            }
            g2.draw(new Line2D.Float(p1.x * z, p1.y * z, p2.x * z, p2.y * z));
            handle(g2, p1.x * z, p1.y * z);
            handle(g2, p2.x * z, p2.y * z);
            return;
        }
        g2.draw(px);
        if (kind == Kind.BOX)
            for (Point2D.Float h : handles(px))
                handle(g2, h.x, h.y);
    }

    private static void handle(Graphics2D g2, float x, float y) {
        int s = HANDLE_PX;
        g2.setColor(Color.WHITE);
        g2.fillRect(Math.round(x) - s / 2, Math.round(y) - s / 2, s, s);
        g2.setColor(new Color(30, 110, 220));
        g2.drawRect(Math.round(x) - s / 2, Math.round(y) - s / 2, s, s);
    }

    /** The eight handles of a box, in pixels: corners then edge midpoints (NW, NE, SW, SE, N, S, W, E). */
    private static Point2D.Float[] handles(Rectangle2D.Float r) {
        float cx = r.x + r.width / 2, cy = r.y + r.height / 2;
        return new Point2D.Float[]{
                new Point2D.Float(r.x, r.y), new Point2D.Float(r.x + r.width, r.y),
                new Point2D.Float(r.x, r.y + r.height), new Point2D.Float(r.x + r.width, r.y + r.height),
                new Point2D.Float(cx, r.y), new Point2D.Float(cx, r.y + r.height),
                new Point2D.Float(r.x, cy), new Point2D.Float(r.x + r.width, cy)};
    }

    /** @return the handle index under a view point (line: 0 = start, 1 = end), -1 when none or the kind has none */
    private int handleAt(PDFToolContext c, PageTransform t, Point2D.Float viewPt) {
        Kind kind = AnnotationGeometry.kind(selected);
        float z = c.zoom();
        float tol = (HANDLE_PX / 2f + 1) / z;
        if (kind == Kind.LINE) {
            float[] l = ((PDAnnotationLine) selected).getLine();
            if (l == null || l.length < 4)
                return -1;
            Point2D.Float p1 = t.toView(new Point2D.Float(l[0], l[1])), p2 = t.toView(new Point2D.Float(l[2], l[3]));
            if (p1.distance(viewPt) <= tol)
                return 0;
            if (p2.distance(viewPt) <= tol)
                return 1;
            return -1;
        }
        if (kind != Kind.BOX)
            return -1;
        Rectangle2D.Float r = AnnotationGeometry.bounds(selected, t);
        Point2D.Float[] hs = handles(r);
        for (int i = 0; i < hs.length; i++)
            if (hs[i].distance(viewPt) <= tol)
                return i;
        return -1;
    }

    /** Resizes a view-space rectangle by dragging one handle (see {@link #handles}). */
    static Rectangle2D.Float resized(Rectangle2D.Float r, int handle, float dx, float dy) {
        float x1 = r.x, y1 = r.y, x2 = r.x + r.width, y2 = r.y + r.height;
        switch (handle) {
            case 0: x1 += dx; y1 += dy; break;
            case 1: x2 += dx; y1 += dy; break;
            case 2: x1 += dx; y2 += dy; break;
            case 3: x2 += dx; y2 += dy; break;
            case 4: y1 += dy; break;
            case 5: y2 += dy; break;
            case 6: x1 += dx; break;
            case 7: x2 += dx; break;
            default: break;
        }
        float minX = Math.min(x1, x2), minY = Math.min(y1, y2);
        return new Rectangle2D.Float(minX, minY, Math.max(1f, Math.abs(x2 - x1)), Math.max(1f, Math.abs(y2 - y1)));
    }

    /**
     * Resizes a view-space rectangle by dragging a corner handle (0-3, see
     * {@link #handles}) while keeping its aspect ratio: the width follows the
     * drag, the height follows the width, the opposite corner stays put.
     */
    static Rectangle2D.Float resizedKeepingAspect(Rectangle2D.Float r, int handle, float dx, float dy) {
        if (handle < 0 || handle > 3 || r.height <= 0)
            return resized(r, handle, dx, dy);
        float aspect = r.width / r.height;
        boolean left = handle == 0 || handle == 2, top = handle == 0 || handle == 1;
        float w = r.width + (left ? -dx : dx);
        float h = r.height + (top ? -dy : dy);
        // whichever of the two drags asks for the bigger box wins, so the pointer stays outside the box
        if (h * aspect > w)
            w = h * aspect;
        w = Math.max(1f, w);
        h = Math.max(1f, w / aspect);
        float x = left ? r.x + r.width - w : r.x;
        float y = top ? r.y + r.height - h : r.y;
        return new Rectangle2D.Float(x, y, w, h);
    }

    private String label() {
        return selected == null ? "annotation" : labelOf(selected);
    }

    /**
     * @return a short lower-case name for an annotation as the editor calls it
     *         ("text box", "image", "highlight", ...), for edit names and status text
     */
    public static String describe(PDAnnotation a) {
        return labelOf(a);
    }

    private static String labelOf(PDAnnotation a) {
        String sub = AnnotationFactory.subtype(a);
        if (sub == null)
            return "annotation";
        switch (sub) {
            case "Highlight": return "highlight";
            case "Underline": return "underline";
            case "StrikeOut": return "strikeout";
            case "Text": return "note";
            case "FreeText": return "text box";
            case "Ink": return "ink";
            case "Square": return "rectangle";
            case "Circle": return "ellipse";
            case "Line": return "line";
            case "Stamp": return ImageStamp.isImage(a) ? "image" : "stamp";
            default: return sub.toLowerCase();
        }
    }

    /**
     * Moves the selected annotation by a view-space delta (undoable).
     *
     * @param dxPt points to the right
     * @param dyPt points down
     * @return true when moved
     */
    public boolean moveSelected(PDFToolContext c, float dxPt, float dyPt) {
        if (selected == null)
            return false;
        PageTransform t = transformOf(c, page);
        if (t == null)
            return false;
        synchronized (c.docLock()) {
            before = ModifyAnnotationEdit.snapshot(selected);
            Point2D.Float from = t.toPdf(new Point2D.Float(0, 0)), to = t.toPdf(new Point2D.Float(dxPt, dyPt));
            AnnotationGeometry.translate(selected, to.x - from.x, to.y - from.y);
            AnnotationFactory.rebuildAppearance(c.document(), selected);
        }
        commit(c, "Move " + label());
        return true;
    }

    /**
     * Resizes the selected box annotation to a view-space rectangle (undoable).
     *
     * @return true when resized
     */
    public boolean resizeSelected(PDFToolContext c, Rectangle2D viewRect) {
        if (selected == null || AnnotationGeometry.kind(selected) != Kind.BOX)
            return false;
        PageTransform t = transformOf(c, page);
        if (t == null)
            return false;
        synchronized (c.docLock()) {
            before = ModifyAnnotationEdit.snapshot(selected);
            AnnotationGeometry.setBounds(selected, t.toPdfRect(viewRect));
            AnnotationFactory.rebuildAppearance(c.document(), selected);
        }
        commit(c, "Resize " + label());
        return true;
    }

    /**
     * Turns the selected image stamp by a quarter turn (undoable): the picture
     * is redrawn rotated about the centre of its box and the box's sides are
     * swapped, kept on the page when it fits.
     *
     * @param delta degrees clockwise, a multiple of 90 (negative = counter-clockwise)
     * @return true when turned, false when nothing or no image stamp is selected
     */
    public boolean rotateSelected(PDFToolContext c, int delta) {
        if (selected == null || !ImageStamp.isImage(selected) || delta % 360 == 0)
            return false;
        PageTransform t = transformOf(c, page);
        if (t == null)
            return false;
        synchronized (c.docLock()) {
            before = ModifyAnnotationEdit.snapshot(selected);
            ImageStamp.rotate(selected, delta, t.toPdfRect(new Rectangle2D.Float(0, 0, t.widthPt(), t.heightPt())));
            AnnotationFactory.rebuildAppearance(c.document(), selected);
        }
        commit(c, (delta % 360 + 360) % 360 == 270 ? "Rotate image left" : "Rotate image right");
        return true;
    }

    /** Rectangle of the selected annotation in PDF space, for tests and the pane. */
    public PDRectangle selectedRect() {
        return selected == null ? null : selected.getRectangle();
    }

    @Override
    public Cursor cursor() {
        return Cursor.getDefaultCursor();
    }

    @Override
    public boolean followsLinks() {
        return false;
    }

    /** @return the page's editable annotations (no popups, links, widgets) */
    public List<PDAnnotation> editableAnnotations(PDFToolContext c, int page) {
        List<PDAnnotation> all = new java.util.ArrayList<>(annotationsOf(c, page)); // never filter the page's live list
        all.removeIf(a -> !AnnotationGeometry.isEditable(a));
        return all;
    }
}
