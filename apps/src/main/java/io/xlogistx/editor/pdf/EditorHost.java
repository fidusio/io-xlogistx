package io.xlogistx.editor.pdf;

import io.xlogistx.gui.pdf.PDFToolHandler;
import io.xlogistx.gui.pdf.PDFViewerPanel;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;

import javax.swing.JComponent;

/**
 * What an editing tool needs from the editor that owns it: the viewer, the
 * undo model, the style to create annotations with, a parent for dialogs, and
 * callbacks for tool and selection changes. Implemented by {@link PDFEditorPane}.
 */
public interface EditorHost {

    /** Which style a tool asks for. */
    enum StyleKey {
        HIGHLIGHT, UNDERLINE, STRIKEOUT, NOTE, DRAWING, TEXT, IMAGE
    }

    /** @return the viewer the tools act on */
    PDFViewerPanel viewer();

    /** @return the undo model every edit goes through */
    PDFEditModel model();

    /** @return the style for new annotations of that kind, never null */
    AnnotationStyle style(StyleKey key);

    /** @return the component dialogs are parented to */
    JComponent dialogParent();

    /** A tool was deactivated (the viewer switched to another tool). @param tool the tool */
    void toolDeactivated(PDFToolHandler tool);

    /**
     * The selection tool selected (or deselected) an annotation.
     *
     * @param page zero-based page, -1 when nothing is selected
     * @param a    the annotation, null when nothing is selected
     */
    void annotationSelected(int page, PDAnnotation a);

    /**
     * Switches to the selection tool with the given annotation selected (a
     * creation tool hands over what it just placed, or an existing annotation
     * the user pressed on).
     *
     * @param page zero-based page
     * @param a    the annotation, never null
     */
    void selectWithTool(int page, PDAnnotation a);
}
