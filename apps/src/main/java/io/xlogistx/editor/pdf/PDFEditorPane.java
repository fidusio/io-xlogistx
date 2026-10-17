package io.xlogistx.editor.pdf;

import io.xlogistx.editor.pdf.AnnotationFactory.MarkupKind;
import io.xlogistx.editor.pdf.tools.EditTextTool;
import io.xlogistx.editor.pdf.tools.EditorTool;
import io.xlogistx.editor.pdf.tools.FormFillTool;
import io.xlogistx.editor.pdf.tools.FreeTextTool;
import io.xlogistx.editor.pdf.tools.ImageTool;
import io.xlogistx.editor.pdf.tools.InkTool;
import io.xlogistx.editor.pdf.tools.LineTool;
import io.xlogistx.editor.pdf.tools.NoteTool;
import io.xlogistx.editor.pdf.tools.SelectAnnotationTool;
import io.xlogistx.editor.pdf.tools.ShapeTool;
import io.xlogistx.editor.pdf.tools.TextMarkupTool;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.PDFToolContext;
import io.xlogistx.gui.PDFToolHandler;
import io.xlogistx.gui.PDFViewerPanel;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationRubberStamp;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDTerminalField;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The embeddable PDF editor: a {@link PDFViewerPanel} whose edits are recorded
 * in a {@link PDFEditModel} so they can be undone, plus an edit row under the
 * viewer's own toolbar with the Edit toggle, Undo/Redo, page rotation and
 * reordering, form filling, text markup, notes, drawing tools, annotation
 * selection and a property strip.
 * <p>
 * The pane installs itself as the viewer's {@link PDFViewerPanel.EditDelegate}:
 * every insert and delete the viewer is asked for becomes an undoable edit, and
 * the viewer's {@link PDFViewerPanel#isModified()} answers from the model, so
 * undoing back to the saved state clears the modified mark. The edit tools are
 * {@link EditorTool}s installed as the viewer's {@link PDFViewerPanel.Tool#CUSTOM}
 * tool; picking Pan, Select text or Zoom in the viewer row deselects them.
 * Loading another document or saving over the open file (which reloads it)
 * clears the history.
 * <p>
 * Hosts install {@link #createMenuBar()} in their window, follow the document
 * through {@link #getDocumentTitle()} and {@link #addChangeListener}, and call
 * {@link #confirmDiscard()} before closing. The pane never exits the JVM.
 * Must be used on the EDT.
 */
public class PDFEditorPane extends JPanel implements EditorHost {

    /** The editing tools of the edit row. */
    public enum EditTool {
        EDIT_TEXT, FORM, HIGHLIGHT, UNDERLINE, STRIKEOUT, NOTE, INK, RECTANGLE, ELLIPSE, LINE, ARROW, TEXT_BOX, IMAGE, SELECT
    }

    private final PDFViewerPanel viewer;
    private final PDFEditModel model = new PDFEditModel();
    private final List<ChangeListener> listeners = new CopyOnWriteArrayList<>();
    private final JToolBar editToolbar;
    private final JToggleButton editToggle;
    private final JButton undoButton;
    private final JButton redoButton;
    private final JButton rotateLeftButton, rotateRightButton, moveButton, deleteAnnotationButton, propertiesButton;
    private static final String ROTATE_PAGE_LEFT_TIP = "Rotate the current page counter-clockwise",
            ROTATE_PAGE_RIGHT_TIP = "Rotate the current page clockwise",
            ROTATE_IMAGE_LEFT_TIP = "Rotate the selected image counter-clockwise (Ctrl+Shift+L)",
            ROTATE_IMAGE_RIGHT_TIP = "Rotate the selected image clockwise (Ctrl+Shift+R)";
    private final Icon rotatePageLeftIcon = new IconUtil.RotateLeftIcon(16), rotatePageRightIcon = new IconUtil.RotateRightIcon(16),
            rotateImageLeftIcon = new IconUtil.RotateImageLeftIcon(16), rotateImageRightIcon = new IconUtil.RotateImageRightIcon(16);
    private final Map<EditTool, EditorTool> tools = new EnumMap<>(EditTool.class);
    private final Map<EditTool, JToggleButton> toolButtons = new EnumMap<>(EditTool.class);
    private final ButtonGroup toolGroup = new ButtonGroup();
    private final JToggleButton noTool = new JToggleButton();
    private final Map<StyleKey, AnnotationStyle> styles = new EnumMap<>(StyleKey.class);
    private final List<JComponent> editControls = new ArrayList<>();
    private final JButton strokeButton, fillButton;
    private final JSpinner opacitySpinner, widthSpinner, sizeSpinner;
    private final JComboBox<String> fontCombo;
    private final JToggleButton boldToggle, italicToggle, underlineToggle, strikeToggle;
    private final JButton highlightButton;
    private final JComboBox<String> alignCombo;
    private boolean updatingStrip;
    private boolean editable;
    private EditTool activeTool;
    private PDAnnotation selectedAnnotation;
    private int selectedPage = -1;

    /** Creates a pane around a new, empty viewer. */
    public PDFEditorPane() {
        this(new PDFViewerPanel());
    }

    /**
     * Creates a pane around the given viewer, moving the viewer's toolbar above
     * the edit row.
     *
     * @param viewer the viewer to edit with, never null
     */
    public PDFEditorPane(PDFViewerPanel viewer) {
        SUS.checkIfNull("viewer null", viewer);
        this.viewer = viewer;
        setLayout(new BorderLayout());
        styles.put(StyleKey.HIGHLIGHT, AnnotationStyle.HIGHLIGHT);
        styles.put(StyleKey.UNDERLINE, AnnotationStyle.UNDERLINE);
        styles.put(StyleKey.STRIKEOUT, AnnotationStyle.UNDERLINE);
        styles.put(StyleKey.NOTE, AnnotationStyle.NOTE);
        styles.put(StyleKey.DRAWING, AnnotationStyle.DRAWING);
        styles.put(StyleKey.TEXT, AnnotationStyle.TEXT);
        styles.put(StyleKey.IMAGE, AnnotationStyle.IMAGE);

        tools.put(EditTool.EDIT_TEXT, new EditTextTool(this));
        tools.put(EditTool.FORM, new FormFillTool(this));
        tools.put(EditTool.HIGHLIGHT, new TextMarkupTool(this, MarkupKind.HIGHLIGHT));
        tools.put(EditTool.UNDERLINE, new TextMarkupTool(this, MarkupKind.UNDERLINE));
        tools.put(EditTool.STRIKEOUT, new TextMarkupTool(this, MarkupKind.STRIKEOUT));
        tools.put(EditTool.NOTE, new NoteTool(this));
        tools.put(EditTool.INK, new InkTool(this));
        tools.put(EditTool.RECTANGLE, new ShapeTool(this, false));
        tools.put(EditTool.ELLIPSE, new ShapeTool(this, true));
        tools.put(EditTool.LINE, new LineTool(this, false));
        tools.put(EditTool.ARROW, new LineTool(this, true));
        tools.put(EditTool.TEXT_BOX, new FreeTextTool(this));
        tools.put(EditTool.IMAGE, new ImageTool(this));
        tools.put(EditTool.SELECT, new SelectAnnotationTool(this));

        editToggle = new JToggleButton(new IconUtil.EditIcon(16));
        editToggle.setToolTipText("Edit: enable editing (undo / redo, page operations, forms, annotations)");
        editToggle.addActionListener(e -> {
            setEditable(editToggle.isSelected());
            if (editable && activeTool == null)
                setActiveTool(EditTool.SELECT); // the natural starting tool: click selects, drag moves or pans
        });
        undoButton = GUIUtil.iconButton(new IconUtil.UndoIcon(16));
        undoButton.addActionListener(e -> undo());
        redoButton = GUIUtil.iconButton(new IconUtil.RedoIcon(16));
        redoButton.addActionListener(e -> redo());

        editToolbar = new JToolBar();
        editToolbar.setFloatable(false);
        editToolbar.add(editToggle);
        editToolbar.addSeparator();
        editToolbar.add(undoButton);
        editToolbar.add(redoButton);
        editToolbar.addSeparator();

        rotateLeftButton = control(GUIUtil.iconButton(rotatePageLeftIcon), ROTATE_PAGE_LEFT_TIP, e -> rotateInContext(-90));
        rotateRightButton = control(GUIUtil.iconButton(rotatePageRightIcon), ROTATE_PAGE_RIGHT_TIP, e -> rotateInContext(90));
        moveButton = control(GUIUtil.iconButton(new IconUtil.MoveIcon(16)), "Move pages to another position...", e -> movePagesDialog());
        editToolbar.addSeparator();
        toolGroup.add(noTool);
        toolButton(EditTool.EDIT_TEXT, new IconUtil.EditTextIcon(16), "Edit text: double click a word or select text and press Enter (Ctrl+E), then type the replacement (same font)");
        toolButton(EditTool.FORM, new IconUtil.FormIcon(16), "Fill form fields: click a field to edit it");
        editToolbar.addSeparator();
        toolButton(EditTool.HIGHLIGHT, new IconUtil.HighlightIcon(16), "Highlight: drag over text (Ctrl+Shift+H marks the selection)");
        toolButton(EditTool.UNDERLINE, new IconUtil.UnderlineIcon(16), "Underline: drag over text");
        toolButton(EditTool.STRIKEOUT, new IconUtil.StrikeoutIcon(16), "Strikeout: drag over text");
        toolButton(EditTool.NOTE, new IconUtil.NoteIcon(16), "Note: click to place a sticky note");
        editToolbar.addSeparator();
        toolButton(EditTool.INK, new IconUtil.PenIcon(16), "Ink: draw freehand");
        toolButton(EditTool.RECTANGLE, new IconUtil.RectangleIcon(16), "Rectangle: drag a box");
        toolButton(EditTool.ELLIPSE, new IconUtil.EllipseIcon(16), "Ellipse: drag a box");
        toolButton(EditTool.LINE, new IconUtil.LineIcon(16), "Line: drag from start to end");
        toolButton(EditTool.ARROW, new IconUtil.ArrowIcon(16), "Arrow: drag from start to the arrow head");
        toolButton(EditTool.TEXT_BOX, new IconUtil.TextBoxIcon(16), "Text box: drag a box (or click) and type");
        toolButton(EditTool.IMAGE, new IconUtil.PictureIcon(16), "Image: drag a box (or click) and pick a picture file; move, resize and rotate it with the Select tool");
        editToolbar.addSeparator();
        toolButton(EditTool.SELECT, new IconUtil.AnnotSelectIcon(16), "Select annotation: click an annotation or image to select it, drag it to move, drag a handle to resize, Delete removes it, double click edits text; a drag on empty space pans");
        deleteAnnotationButton = control(GUIUtil.iconButton(new IconUtil.DeleteIcon(16)), "Delete the selected annotation (Delete)", e -> deleteSelectedAnnotation());
        propertiesButton = control(GUIUtil.iconButton(new IconUtil.InfoIcon(16)), "Properties of the selected annotation...", e -> editSelectedProperties());
        editToolbar.addSeparator();
        strokeButton = control(new JButton(), STROKE_TIP, e -> pickColor(false));
        fillButton = control(new JButton(), "Fill / background colour (none = transparent)", e -> pickColor(true));
        opacitySpinner = spinner(1.0, 0.0, 1.0, 0.1, "Opacity (0-1)");
        widthSpinner = spinner(2.0, 0.0, 50.0, 0.5, "Stroke / border width (pt)");
        sizeSpinner = spinner(12.0, 4.0, 144.0, 1.0, "Font size (pt)");
        fontCombo = EditorDialogs.fontCombo(EditorFonts.DEFAULT_FAMILY);
        fontCombo.setToolTipText("Font of text boxes: the bundled Roboto or any installed TrueType font");
        fontCombo.setMaximumSize(new Dimension(190, 28));
        fontCombo.addActionListener(e -> stripChanged());
        editToolbar.add(fontCombo);
        editControls.add(fontCombo);
        boldToggle = face("B", Font.BOLD, "Bold text");
        italicToggle = face("I", Font.ITALIC, "Italic text");
        underlineToggle = face("<html><u>U</u></html>", Font.PLAIN, "Underlined text");
        strikeToggle = face("<html><s>S</s></html>", Font.PLAIN, "Struck-through text");
        highlightButton = control(new JButton(), "Text highlight colour (behind the text; none = no highlight)", e -> pickHighlight());
        alignCombo = new JComboBox<>(ALIGNMENTS);
        alignCombo.setToolTipText("Text alignment in the box");
        alignCombo.setMaximumSize(new Dimension(90, 28));
        alignCombo.addActionListener(e -> stripChanged());
        editToolbar.add(alignCombo);
        editControls.add(alignCombo);
        editToolbar.add(new JLabel(" "));

        JPanel toolbars = new JPanel();
        toolbars.setLayout(new BoxLayout(toolbars, BoxLayout.Y_AXIS));
        JToolBar viewRow = viewer.getToolbar();
        viewRow.setAlignmentX(LEFT_ALIGNMENT);
        editToolbar.setAlignmentX(LEFT_ALIGNMENT);
        toolbars.add(viewRow);        // re-parents it out of the viewer
        viewRow.setVisible(true);
        toolbars.add(editToolbar);
        add(toolbars, BorderLayout.NORTH);
        add(viewer, BorderLayout.CENTER);

        viewer.setEditDelegate(new Delegate());
        model.addListener((m, edit, undo) -> {
            if (edit.structural())
                formTool().refresh(viewer.getToolContext());
            changed();
        });
        viewer.addPageChangeListener((page, count) -> changed());

        InputMap im = getInputMap(WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap am = getActionMap();
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK), "undo", e -> undo());
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_Y, InputEvent.CTRL_DOWN_MASK), "redo", e -> redo());
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), "redo", e -> redo());
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_H, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), "highlightSelection", e -> markSelection(MarkupKind.HIGHLIGHT));
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "deleteAnnotation", e -> deleteSelectedAnnotation());
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_E, InputEvent.CTRL_DOWN_MASK), "editText", e -> editSelectedText());
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), "rotateImageLeft", e -> rotateSelectedImage(-90));
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), "rotateImageRight", e -> rotateSelectedImage(90));
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_F1, 0), "howTo", e -> showHowTo());

        updateStrip();
        updateButtons();
    }

    private <T extends AbstractButton> T control(T b, String tooltip, ActionListener action) {
        b.setToolTipText(tooltip);
        b.addActionListener(action);
        editToolbar.add(b);
        editControls.add(b);
        return b;
    }

    private void toolButton(EditTool tool, Icon icon, String tooltip) {
        JToggleButton b = new JToggleButton(icon);
        b.setToolTipText(tooltip);
        b.addActionListener(e -> setActiveTool(b.isSelected() ? tool : null));
        toolGroup.add(b);
        toolButtons.put(tool, b);
        editToolbar.add(b);
        editControls.add(b);
    }

    private JToggleButton face(String text, int style, String tooltip) {
        JToggleButton b = new JToggleButton(text);
        b.setFont(b.getFont().deriveFont(style, 13f));
        b.setToolTipText(tooltip);
        b.setFocusable(false);
        b.setMargin(new Insets(2, 6, 2, 6));
        b.addActionListener(e -> stripChanged());
        editToolbar.add(b);
        editControls.add(b);
        return b;
    }

    /** @return true when the strip edits text (a text box being made, or a selected one) */
    private boolean textStrip() {
        return activeTool == EditTool.TEXT_BOX || selectedAnnotation instanceof org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFreeText;
    }

    private JSpinner spinner(double value, double min, double max, double step, String tooltip) {
        JSpinner s = new JSpinner(new SpinnerNumberModel(value, min, max, step));
        s.setToolTipText(tooltip);
        s.setMaximumSize(new Dimension(64, 28));
        s.addChangeListener(e -> stripChanged());
        editToolbar.add(s);
        editControls.add(s);
        return s;
    }

    private static void bind(InputMap im, ActionMap am, KeyStroke key, String name, ActionListener action) {
        im.put(key, name);
        am.put(name, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                action.actionPerformed(e);
            }
        });
    }

    // ------------------------------------------------------------------ accessors

    /** @return the viewer */
    public PDFViewerPanel getViewer() {
        return viewer;
    }

    /** @return the undo/redo model */
    public PDFEditModel getEditModel() {
        return model;
    }

    /** @return the edit row, so hosts can add controls */
    public JToolBar getEditToolbar() {
        return editToolbar;
    }

    /**
     * Turns editing on or off: Undo/Redo, page operations, form filling and the
     * annotation tools work only while on. Page edits made through the viewer
     * are recorded either way, so turning it on later still offers to undo them.
     * Turning it off deselects the active tool (the viewer falls back to Pan).
     *
     * @param on whether editing is enabled
     * @return this pane, for chaining
     */
    public PDFEditorPane setEditable(boolean on) {
        editable = on;
        if (editToggle.isSelected() != on)
            editToggle.setSelected(on);
        if (!on && activeTool != null)
            setActiveTool(null);
        updateButtons();
        changed();
        return this;
    }

    /** @return whether editing is enabled */
    public boolean isEditable() {
        return editable;
    }

    /** @return whether editing is on and there is an edit to undo */
    public boolean canUndo() {
        return editable && model.canUndo();
    }

    /** @return whether editing is on and there is an edit to redo */
    public boolean canRedo() {
        return editable && model.canRedo();
    }

    /** Reverts the most recent edit, if editing is on. @return this pane */
    public PDFEditorPane undo() {
        if (!canUndo())
            return this;
        clearAnnotationSelection();
        try {
            model.undo();
        } catch (IOException e) {
            showError("Undo failed: " + e.getMessage());
        }
        return this;
    }

    /** Re-applies the most recently undone edit, if editing is on. @return this pane */
    public PDFEditorPane redo() {
        if (!canRedo())
            return this;
        clearAnnotationSelection();
        try {
            model.redo();
        } catch (IOException e) {
            showError("Redo failed: " + e.getMessage());
        }
        return this;
    }

    /** @return whether the document has unsaved changes */
    public boolean isModified() {
        return viewer.isModified();
    }

    /**
     * Asks whether unsaved changes may be discarded.
     *
     * @return true if there is nothing to lose or the user chose to discard
     */
    public boolean confirmDiscard() {
        return viewer.confirmDiscard();
    }

    /**
     * @return the file name (plus {@code " *"} when modified), {@code "Untitled"}
     *         for a document without a file, empty when nothing is loaded
     */
    public String getDocumentTitle() {
        String title = "";
        File f = viewer.getFile();
        if (f != null)
            title = f.getName();
        else if (viewer.getDocument() != null)
            title = "Untitled";
        if (!title.isEmpty() && isModified())
            title += " *";
        return title;
    }

    /** @param l notified on every edit, page change, load, save, tool and selection change; never null */
    public void addChangeListener(ChangeListener l) {
        SUS.checkIfNull("listener null", l);
        listeners.add(l);
    }

    /** @param l the listener to remove */
    public void removeChangeListener(ChangeListener l) {
        listeners.remove(l);
    }

    // ------------------------------------------------------------------ tools

    /**
     * Selects an editing tool (enables editing if needed); null returns the
     * viewer to Pan.
     *
     * @param tool the tool, may be null
     * @return this pane
     */
    public PDFEditorPane setActiveTool(EditTool tool) {
        if (tool == null) {
            if (activeTool != null) {
                activeTool = null;
                viewer.setTool(PDFViewerPanel.Tool.PAN); // deactivates the custom handler -> toolDeactivated
            }
            noTool.setSelected(true);
            updateButtons();
            return this;
        }
        if (!editable)
            setEditable(true);
        if (activeTool == tool && viewer.getTool() == PDFViewerPanel.Tool.CUSTOM)
            return this;
        activeTool = tool;
        viewer.setCustomTool(tools.get(tool));
        JToggleButton b = toolButtons.get(tool);
        if (!b.isSelected())
            b.setSelected(true);
        updateStrip();
        updateButtons();
        changed();
        return this;
    }

    /** @return the active editing tool, null when a viewer tool (pan, select text, zoom) is active */
    public EditTool getActiveTool() {
        return activeTool;
    }

    /** @return the handler behind an editing tool */
    public EditorTool getTool(EditTool tool) {
        return tools.get(tool);
    }

    private SelectAnnotationTool selectTool() {
        return (SelectAnnotationTool) tools.get(EditTool.SELECT);
    }

    private FormFillTool formTool() {
        return (FormFillTool) tools.get(EditTool.FORM);
    }

    private ImageTool imageTool() {
        return (ImageTool) tools.get(EditTool.IMAGE);
    }

    private PDFToolContext ctx() {
        return viewer.getToolContext();
    }

    // ------------------------------------------------------------------ page operations

    /**
     * Rotates pages (undoable).
     *
     * @param pages zero-based pages
     * @param delta degrees, a multiple of 90 (positive = clockwise)
     * @return true when applied
     */
    public boolean rotatePages(int[] pages, int delta) {
        return applyEdit(new RotatePagesEdit(viewer, pages, delta));
    }

    /**
     * Moves pages (undoable), see {@link MovePagesEdit} for the target semantics.
     *
     * @return true when applied
     */
    public boolean movePages(int[] pages, int target) {
        return applyEdit(new MovePagesEdit(viewer, pages, target));
    }

    /**
     * The toolbar rotate buttons: an image stamp selected with the Select tool is rotated
     * ({@link #rotateSelectedImage}), otherwise the current page ({@link #rotatePages}); the
     * buttons switch icon and tooltip with the selection in {@code updateButtons()}.
     *
     * @param delta +90 clockwise, -90 counter-clockwise
     */
    private void rotateInContext(int delta) {
        if (selectedAnnotation != null && ImageStamp.isImage(selectedAnnotation))
            rotateSelectedImage(delta);
        else
            rotateCurrentPage(delta);
    }

    private void rotateCurrentPage(int delta) {
        int p = viewer.getCurrentPage();
        if (p >= 0)
            rotatePages(new int[]{p}, delta);
    }

    /** Asks for pages and rotates them. @return true when applied */
    public boolean rotatePagesDialog(int delta) {
        if (viewer.getPageCount() == 0)
            return false;
        int[] r = EditorDialogs.askPages(this, delta > 0 ? "Rotate clockwise" : "Rotate counter-clockwise",
                "Pages to rotate:", viewer.getCurrentPage(), viewer.getPageCount(), false);
        return r != null && rotatePages(EditorDialogs.pagesOf(r), delta);
    }

    /** Asks for pages and a position and moves them. @return true when applied */
    public boolean movePagesDialog() {
        if (viewer.getPageCount() < 2)
            return false;
        int[] r = EditorDialogs.askPages(this, "Move pages", "Pages to move:", viewer.getCurrentPage(), viewer.getPageCount(), true);
        return r != null && movePages(EditorDialogs.pagesOf(r), EditorDialogs.targetOf(r));
    }

    // ------------------------------------------------------------------ page text

    /**
     * Opens the replacement dialog for the selected page text (editing is
     * turned on; the selection must lie on one page).
     *
     * @return true when the text was replaced
     */
    public boolean editSelectedText() {
        if (!viewer.hasSelection())
            return false;
        if (!editable)
            setEditable(true);
        return ((EditTextTool) tools.get(EditTool.EDIT_TEXT)).editSelection(ctx());
    }

    /**
     * Replaces the selected page text in place with the same font (undoable).
     * Characters the font cannot show are refused with an error dialog.
     *
     * @param replacement the new text, empty deletes the selection
     * @return true when replaced
     */
    public boolean replaceSelectedText(String replacement) {
        return replaceSelectedText(replacement, TextEditor.Alignment.LEFT);
    }

    /**
     * Replaces the selected page text in place with the same font (undoable),
     * placing it by {@code alignment} inside the room the old text took: left
     * keeps the original start, right the original end, centre the middle.
     *
     * @param replacement the new text, empty deletes the selection
     * @param alignment   where the replacement sits
     * @return true when replaced
     */
    public boolean replaceSelectedText(String replacement, TextEditor.Alignment alignment) {
        return replaceSelectedText(replacement, alignment, TextEditor.Format.SAME);
    }

    /**
     * Replaces the selected page text in place (undoable), placed by
     * {@code alignment} and written with the font, size and colour the format
     * gives; what the format leaves out (null family, size 0, null colour) is
     * kept from the old text. Another font is embedded into the page, so any
     * character that font has can be typed.
     *
     * @param replacement the new text, empty deletes the selection
     * @param alignment   where the replacement sits
     * @param format      font, size and colour; null = keep all
     * @return true when replaced
     */
    public boolean replaceSelectedText(String replacement, TextEditor.Alignment alignment, TextEditor.Format format) {
        SUS.checkIfNull("replacement null", replacement);
        if (!editable)
            setEditable(true);
        return ((EditTextTool) tools.get(EditTool.EDIT_TEXT)).replaceSelection(ctx(), replacement, alignment, format);
    }

    // ------------------------------------------------------------------ annotations

    /**
     * Marks the current text selection (one annotation per page, one undo step).
     *
     * @return the number of annotations added
     */
    public int markSelection(MarkupKind kind) {
        if (!editable || !viewer.hasSelection())
            return 0;
        return TextMarkupTool.mark(ctx(), this, kind);
    }

    /**
     * Adds a sticky note (undoable).
     *
     * @param page   zero-based page
     * @param viewPt top-left of the icon in view space (points, top-left origin)
     * @param text   the note text
     * @return the note, null when not added
     */
    public PDAnnotation addNote(int page, Point2D viewPt, String text) {
        return ((NoteTool) tools.get(EditTool.NOTE)).addNote(ctx(), page, viewPt, text);
    }

    /**
     * Adds any annotation (with its appearance already built) to a page, undoable.
     *
     * @return true when applied
     */
    public boolean addAnnotation(int page, PDAnnotation a) {
        return applyEdit(new AddAnnotationEdit(viewer, page, a));
    }

    /**
     * Places an image file on a page as an image stamp (undoable, embedded in
     * the document; JPEG data as is, other formats losslessly).
     *
     * @param page     zero-based page
     * @param viewRect the box in view space (points, top-left origin); the
     *                 picture is fitted into it keeping its aspect ratio; a
     *                 sizeless rectangle places the picture at its own size at
     *                 that corner, null at the page's top-left margin
     * @param file     the image file
     * @return the stamp, null when not added (an error is shown)
     */
    public PDAnnotation addImage(int page, Rectangle2D viewRect, File file) {
        if (!editable)
            setEditable(true);
        return imageTool().addImage(ctx(), page, viewRect, file);
    }

    /**
     * Places a picture on a page as an image stamp (undoable, embedded losslessly).
     *
     * @param viewRect see {@link #addImage(int, Rectangle2D, File)}
     * @return the stamp, null when not added
     */
    public PDAnnotation addImage(int page, Rectangle2D viewRect, BufferedImage picture) {
        if (!editable)
            setEditable(true);
        return imageTool().addImage(ctx(), page, viewRect, picture);
    }

    /**
     * Asks for an image file and places it on the current page at its own size
     * (menu action).
     *
     * @return true when an image was added
     */
    public boolean insertImageDialog() {
        int page = viewer.getCurrentPage();
        if (page < 0)
            return false;
        File file = imageTool().chooseFile();
        if (file == null)
            return false;
        PDAnnotation a = addImage(page, null, file);
        if (a == null)
            return false;
        selectAnnotation(page, a);
        return true;
    }

    /** Removes an annotation (undoable). @return true when applied */
    public boolean removeAnnotation(int page, PDAnnotation a) {
        if (selectedAnnotation != null && selectedAnnotation.getCOSObject() == a.getCOSObject())
            clearAnnotationSelection();
        return applyEdit(new RemoveAnnotationEdit(viewer, page, a));
    }

    /** @return the page's editable annotations (no popups, links or form widgets); a snapshot */
    public List<PDAnnotation> getAnnotations(int page) {
        return selectTool().editableAnnotations(ctx(), page);
    }

    /** @return the selected annotation, null when none */
    public PDAnnotation getSelectedAnnotation() {
        return selectedAnnotation;
    }

    /** @return the selected annotation's page, -1 when none */
    public int getSelectedAnnotationPage() {
        return selectedAnnotation == null ? -1 : selectedPage;
    }

    /** Selects an annotation with the selection tool (activating it). */
    public PDFEditorPane selectAnnotation(int page, PDAnnotation a) {
        setActiveTool(EditTool.SELECT);
        selectTool().select(ctx(), page, a);
        return this;
    }

    /** Clears the annotation selection without changing the tool. */
    public PDFEditorPane clearAnnotationSelection() {
        if (selectedAnnotation != null)
            selectTool().select(ctx(), -1, null);
        return this;
    }

    /** Deletes the selected annotation (undoable). @return true when one was deleted */
    public boolean deleteSelectedAnnotation() {
        return editable && selectedAnnotation != null && selectTool().deleteSelected(ctx());
    }

    /** Opens the properties dialog for the selected annotation. @return true when changed */
    public boolean editSelectedProperties() {
        return editable && selectedAnnotation != null && selectTool().editProperties(ctx());
    }

    /**
     * Turns the selected image by a quarter turn (undoable); see
     * {@link ImageStamp#rotate}.
     *
     * @param delta degrees clockwise, a multiple of 90 (negative = counter-clockwise)
     * @return true when turned, false when no image is selected
     */
    public boolean rotateSelectedImage(int delta) {
        return editable && selectedAnnotation != null && selectTool().rotateSelected(ctx(), delta);
    }

    /** Applies a style to the selected annotation (undoable). @return true when applied */
    public boolean applyStyleToSelection(AnnotationStyle style) {
        return editable && selectedAnnotation != null && selectTool().applyStyle(ctx(), style);
    }

    // ------------------------------------------------------------------ forms

    /** @return the document's fillable and non-fillable terminal form fields, empty without a form */
    public List<PDTerminalField> getFormFields() {
        synchronized (viewer.getDocumentLock()) {
            PDDocument doc = viewer.getDocument();
            return doc == null ? Collections.<PDTerminalField>emptyList() : FormFields.fields(doc);
        }
    }

    /**
     * Sets a form field's value (undoable).
     *
     * @param field the field
     * @param value a String, or a List of Strings for a multi-select choice
     * @return true when applied
     */
    public boolean setFieldValue(PDField field, Object value) {
        return formTool().setValue(ctx(), field, value);
    }

    // ------------------------------------------------------------------ styles

    /** @return the style new annotations of that kind get */
    public AnnotationStyle getStyle(StyleKey key) {
        return styles.get(key);
    }

    /** Sets the style new annotations of that kind get. @return this pane */
    public PDFEditorPane setStyle(StyleKey key, AnnotationStyle style) {
        SUS.checkIfNull("style null", style);
        styles.put(key, style);
        updateStrip();
        return this;
    }

    /** The style key the property strip edits for the active tool, null when the strip is idle. */
    private StyleKey stripKey() {
        if (activeTool == null)
            return null;
        switch (activeTool) {
            case HIGHLIGHT:
                return StyleKey.HIGHLIGHT;
            case UNDERLINE:
                return StyleKey.UNDERLINE;
            case STRIKEOUT:
                return StyleKey.STRIKEOUT;
            case NOTE:
                return StyleKey.NOTE;
            case INK:
            case RECTANGLE:
            case ELLIPSE:
            case LINE:
            case ARROW:
                return StyleKey.DRAWING;
            case TEXT_BOX:
                return StyleKey.TEXT;
            case IMAGE:
                return StyleKey.IMAGE;
            default:
                return null;
        }
    }

    private AnnotationStyle stripStyle() {
        if (activeTool == EditTool.SELECT && selectedAnnotation != null)
            return selectTool().styleOf(ctx());
        StyleKey key = stripKey();
        return key == null ? null : styles.get(key);
    }

    private void updateStrip() {
        updatingStrip = true;
        try {
            AnnotationStyle s = stripStyle();
            boolean on = editable && s != null;
            boolean image = imageStrip();
            strokeButton.setEnabled(on && !image);
            fillButton.setEnabled(on && !image);
            opacitySpinner.setEnabled(on);
            widthSpinner.setEnabled(on && !image);
            sizeSpinner.setEnabled(on && textStrip());
            fontCombo.setEnabled(on && textStrip());
            boldToggle.setEnabled(on && textStrip());
            italicToggle.setEnabled(on && textStrip());
            underlineToggle.setEnabled(on && textStrip());
            strikeToggle.setEnabled(on && textStrip());
            highlightButton.setEnabled(on && textStrip());
            alignCombo.setEnabled(on && textStrip());
            strokeButton.setToolTipText(textStrip() ? FONT_TIP : STROKE_TIP);
            paintSwatch(strokeButton, s == null ? null : s.getStrokeColor(), false);
            paintSwatch(fillButton, s == null ? null : s.getFillColor(), true);
            paintSwatch(highlightButton, s == null ? null : s.getHighlightColor(), true);
            if (s != null) {
                opacitySpinner.setValue((double) s.getOpacity());
                widthSpinner.setValue((double) s.getStrokeWidth());
                sizeSpinner.setValue((double) s.getFontSize());
                EditorDialogs.selectFamily(fontCombo, s.getFontFamily());
                boldToggle.setSelected(s.isBold());
                italicToggle.setSelected(s.isItalic());
                underlineToggle.setSelected(s.isUnderline());
                strikeToggle.setSelected(s.isStrikethrough());
                alignCombo.setSelectedIndex(s.getAlignment().ordinal());
            }
        } finally {
            updatingStrip = false;
        }
    }

    /** @return true when the strip edits an image stamp's style (opacity only) */
    private boolean imageStrip() {
        return activeTool == EditTool.IMAGE || (activeTool == EditTool.SELECT && selectedAnnotation instanceof PDAnnotationRubberStamp);
    }

    private void stripChanged() {
        if (updatingStrip)
            return;
        AnnotationStyle s = stripStyle();
        if (s == null)
            return;
        AnnotationStyle n = s.withOpacity(((Number) opacitySpinner.getValue()).floatValue())
                .withStrokeWidth(((Number) widthSpinner.getValue()).floatValue())
                .withFontSize(((Number) sizeSpinner.getValue()).floatValue())
                .withFontFamily((String) fontCombo.getSelectedItem())
                .withFontStyle((boldToggle.isSelected() ? Font.BOLD : 0) | (italicToggle.isSelected() ? Font.ITALIC : 0))
                .withUnderline(underlineToggle.isSelected())
                .withStrikethrough(strikeToggle.isSelected())
                .withAlignment(TextEditor.Alignment.values()[Math.max(0, alignCombo.getSelectedIndex())]);
        commitStripStyle(n);
    }

    /** The alignment combo's entries, in {@link TextEditor.Alignment} order. */
    private static final String[] ALIGNMENTS = {"Left", "Centre", "Right"};

    private static final String STROKE_TIP = "Colour (stroke / highlight / note icon)", FONT_TIP = "Font colour of the text";

    private void pickColor(boolean fill) {
        AnnotationStyle s = stripStyle();
        if (s == null)
            return;
        Color current = fill ? s.getFillColor() : s.getStrokeColor();
        Color chosen = JColorChooser.showDialog(this, fill ? "Fill colour" : textStrip() ? "Font colour" : "Colour", current == null ? Color.WHITE : current);
        if (chosen == null) {
            if (fill && current != null && JOptionPane.showConfirmDialog(this, "Remove the fill?", "Fill colour", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION)
                commitStripStyle(s.withFillColor(null));
            return;
        }
        commitStripStyle(fill ? s.withFillColor(chosen) : s.withStrokeColor(chosen));
    }

    private void pickHighlight() {
        AnnotationStyle s = stripStyle();
        if (s == null)
            return;
        Color current = s.getHighlightColor();
        Color chosen = JColorChooser.showDialog(this, "Text highlight colour", current == null ? AnnotationStyle.MARKER_YELLOW : current);
        if (chosen == null) {
            if (current != null && JOptionPane.showConfirmDialog(this, "Remove the highlight?", "Text highlight", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION)
                commitStripStyle(s.withHighlightColor(null));
            return;
        }
        commitStripStyle(s.withHighlightColor(chosen));
    }

    private void commitStripStyle(AnnotationStyle n) {
        if (activeTool == EditTool.SELECT && selectedAnnotation != null) {
            selectTool().applyStyle(ctx(), n);
        } else {
            StyleKey key = stripKey();
            if (key != null)
                styles.put(key, n);
        }
        updateStrip();
    }

    private static void paintSwatch(JButton b, Color c, boolean allowNone) {
        b.setText(null);
        b.setIcon(new Icon() {
            @Override
            public void paintIcon(Component comp, Graphics g, int x, int y) {
                if (c == null) {
                    g.setColor(Color.GRAY);
                    g.drawRect(x, y, 13, 13);
                    if (allowNone)
                        g.drawLine(x, y + 13, x + 13, y);
                } else {
                    g.setColor(c);
                    g.fillRect(x, y, 14, 14);
                    g.setColor(Color.DARK_GRAY);
                    g.drawRect(x, y, 13, 13);
                }
            }

            @Override
            public int getIconWidth() {
                return 14;
            }

            @Override
            public int getIconHeight() {
                return 14;
            }
        });
    }

    // ------------------------------------------------------------------ file actions

    /**
     * Loads a PDF, Markdown or image file (see {@link PDFViewerPanel#setPDF(File)}).
     *
     * @param file the file, never null
     * @return this pane
     */
    public PDFEditorPane open(File file) {
        SUS.checkIfNull("file null", file);
        viewer.setPDF(file);
        return this;
    }

    /**
     * Saves over the open PDF file, or asks for a file when the document has
     * none or came from a converted source (Markdown, image).
     *
     * @return this pane
     */
    public PDFEditorPane save() {
        File f = viewer.getFile();
        if (f != null && f.getName().toLowerCase().endsWith(".pdf"))
            viewer.save(f);
        else
            viewer.saveAs();
        return this;
    }

    /** Asks for a file and saves. @return the file written, null when cancelled or nothing is loaded */
    public File saveAs() {
        return viewer.saveAs();
    }

    /**
     * Builds the menu bar for a host window: File, Edit, Page, Annotate, Form.
     *
     * @return a new menu bar
     */
    public JMenuBar createMenuBar() {
        JMenuBar bar = new JMenuBar();

        JMenu file = new JMenu("File");
        file.setMnemonic(KeyEvent.VK_F);
        file.add(item("Open...", KeyEvent.VK_O, KeyStroke.getKeyStroke(KeyEvent.VK_O, InputEvent.CTRL_DOWN_MASK), e -> viewer.openFile()));
        file.addSeparator();
        file.add(item("Save", KeyEvent.VK_S, KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK), e -> save()));
        file.add(item("Save As...", KeyEvent.VK_A, KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), e -> saveAs()));
        file.addSeparator();
        file.add(item("Print...", KeyEvent.VK_P, KeyStroke.getKeyStroke(KeyEvent.VK_P, InputEvent.CTRL_DOWN_MASK), e -> viewer.print()));
        bar.add(file);

        JMenu edit = new JMenu("Edit");
        edit.setMnemonic(KeyEvent.VK_E);
        edit.add(item("Undo", KeyEvent.VK_U, KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK), e -> undo()));
        edit.add(item("Redo", KeyEvent.VK_R, KeyStroke.getKeyStroke(KeyEvent.VK_Y, InputEvent.CTRL_DOWN_MASK), e -> redo()));
        edit.addSeparator();
        edit.add(item("Edit selected text...", KeyEvent.VK_T, KeyStroke.getKeyStroke(KeyEvent.VK_E, InputEvent.CTRL_DOWN_MASK), e -> editSelectedText()));
        edit.addSeparator();
        JCheckBoxMenuItem editing = new JCheckBoxMenuItem("Editing enabled", editable);
        editing.addActionListener(e -> setEditable(editing.isSelected()));
        addChangeListener(e -> editing.setSelected(editable));
        edit.add(editing);
        bar.add(edit);

        JMenu page = new JMenu("Page");
        page.setMnemonic(KeyEvent.VK_P);
        page.add(item("Insert...", KeyEvent.VK_I, null, e -> viewer.insertDialog()));
        page.add(item("Delete...", KeyEvent.VK_D, null, e -> viewer.deleteDialog()));
        page.addSeparator();
        page.add(item("Rotate clockwise...", KeyEvent.VK_R, null, e -> rotatePagesDialog(90)));
        page.add(item("Rotate counter-clockwise...", KeyEvent.VK_C, null, e -> rotatePagesDialog(-90)));
        page.add(item("Move...", KeyEvent.VK_M, null, e -> movePagesDialog()));
        bar.add(page);

        JMenu annotate = new JMenu("Annotate");
        annotate.setMnemonic(KeyEvent.VK_A);
        ButtonGroup group = new ButtonGroup();
        Map<EditTool, JRadioButtonMenuItem> items = new EnumMap<>(EditTool.class);
        // the one tool that works on what is already there
        JRadioButtonMenuItem select = new JRadioButtonMenuItem("Select / move / resize (click an annotation or image; drag empty space to pan)");
        select.addActionListener(e -> setActiveTool(EditTool.SELECT));
        group.add(select);
        items.put(EditTool.SELECT, select);
        annotate.add(select);
        JRadioButtonMenuItem none = new JRadioButtonMenuItem("Pan only (no editing tool)", true);
        none.addActionListener(e -> setActiveTool(null));
        group.add(none);
        annotate.add(none);
        annotate.addSeparator();
        annotate.add(item("Delete selected annotation", KeyEvent.VK_D, KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), e -> deleteSelectedAnnotation()));
        annotate.add(item("Properties of selected annotation...", KeyEvent.VK_P, null, e -> editSelectedProperties()));
        annotate.add(item("Rotate selected image counter-clockwise", KeyEvent.VK_L, KeyStroke.getKeyStroke(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), e -> rotateSelectedImage(-90)));
        annotate.add(item("Rotate selected image clockwise", KeyEvent.VK_R, KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), e -> rotateSelectedImage(90)));
        annotate.addSeparator();
        // tools that add something
        Map<EditTool, String> hints = new EnumMap<>(EditTool.class);
        hints.put(EditTool.EDIT_TEXT, "Edit page text (double click a word)");
        hints.put(EditTool.HIGHLIGHT, "Highlight text (drag over it)");
        hints.put(EditTool.UNDERLINE, "Underline text (drag over it)");
        hints.put(EditTool.STRIKEOUT, "Strike out text (drag over it)");
        hints.put(EditTool.NOTE, "Sticky note (click)");
        hints.put(EditTool.INK, "Ink (draw freehand)");
        hints.put(EditTool.RECTANGLE, "Rectangle (drag a box)");
        hints.put(EditTool.ELLIPSE, "Ellipse (drag a box)");
        hints.put(EditTool.LINE, "Line (drag)");
        hints.put(EditTool.ARROW, "Arrow (drag)");
        hints.put(EditTool.TEXT_BOX, "Text box (drag a box, then type)");
        hints.put(EditTool.IMAGE, "Image (drag a box, then pick a picture file)");
        for (EditTool t : new EditTool[]{EditTool.EDIT_TEXT, EditTool.HIGHLIGHT, EditTool.UNDERLINE, EditTool.STRIKEOUT, EditTool.NOTE, EditTool.INK,
                EditTool.RECTANGLE, EditTool.ELLIPSE, EditTool.LINE, EditTool.ARROW, EditTool.TEXT_BOX, EditTool.IMAGE}) {
            JRadioButtonMenuItem mi = new JRadioButtonMenuItem(hints.get(t));
            mi.addActionListener(e -> setActiveTool(t));
            group.add(mi);
            items.put(t, mi);
            if (t == EditTool.HIGHLIGHT || t == EditTool.INK)
                annotate.addSeparator();
            annotate.add(mi);
        }
        annotate.addSeparator();
        annotate.add(item("Insert image on this page...", KeyEvent.VK_M, null, e -> insertImageDialog()));
        annotate.add(item("Highlight selected text", KeyEvent.VK_H, KeyStroke.getKeyStroke(KeyEvent.VK_H, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), e -> markSelection(MarkupKind.HIGHLIGHT)));
        bar.add(annotate);

        JMenu form = new JMenu("Form");
        form.setMnemonic(KeyEvent.VK_M);
        JRadioButtonMenuItem fill = new JRadioButtonMenuItem("Fill form fields");
        fill.addActionListener(e -> setActiveTool(EditTool.FORM));
        group.add(fill);
        items.put(EditTool.FORM, fill);
        form.add(fill);
        bar.add(form);

        JMenu help = new JMenu("Help");
        help.setMnemonic(KeyEvent.VK_H);
        help.add(item("How to use the PDF editor...", KeyEvent.VK_H, KeyStroke.getKeyStroke(KeyEvent.VK_F1, 0), e -> showHowTo()));
        help.addSeparator();
        help.add(item("Version...", KeyEvent.VK_V, null, e -> showVersion()));
        bar.add(help);
        addChangeListener(e -> {
            if (activeTool == null)
                none.setSelected(true);
            else
                items.get(activeTool).setSelected(true);
        });
        return bar;
    }

    // ------------------------------------------------------------------ help

    /** The user guide shipped with the editor, as a resource next to this class. */
    public static final String HOW_TO_RESOURCE = "how-to.md";

    /**
     * @return the user guide (Markdown), or a one-line notice when the resource is missing
     */
    public static String howToMarkdown() {
        try (java.io.InputStream in = PDFEditorPane.class.getResourceAsStream(HOW_TO_RESOURCE)) {
            if (in == null)
                return "# PDF Editor\n\nThe guide (`" + HOW_TO_RESOURCE + "`) is missing from this build.";
            return new String(org.apache.pdfbox.io.IOUtils.toByteArray(in), java.nio.charset.StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "# PDF Editor\n\nThe guide could not be read: " + e.getMessage();
        }
    }

    /**
     * @return the version notice (Markdown): application name and version from
     *         {@link PDFMain#VERSION}, the PDFBox and Java versions
     */
    public static String versionMarkdown() {
        String pdfbox = PDDocument.class.getPackage() == null ? null : PDDocument.class.getPackage().getImplementationVersion();
        return "# " + PDFMain.VERSION.getName() + "\n\n**Version " + PDFMain.VERSION.version() + "**\n\n"
                + "- PDF engine: Apache PDFBox " + (pdfbox == null ? "(version not recorded)" : pdfbox) + "\n"
                + "- Java: " + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")\n"
                + "- Package: `io.xlogistx.editor.pdf`\n";
    }

    /** Shows the user guide in a non-modal window (F1, Help menu), so it can stay open while editing. */
    public void showHowTo() {
        showMarkdown(howToMarkdown(), "How to use the PDF editor", new Dimension(820, 640), false);
    }

    /** Shows the application version (Help menu). */
    public void showVersion() {
        showMarkdown(versionMarkdown(), "Version", new Dimension(420, 260), true);
    }

    private void showMarkdown(String markdown, String title, Dimension size, boolean modal) {
        if (GraphicsEnvironment.isHeadless())
            return;
        io.xlogistx.gui.MDViewerPanel viewer = new io.xlogistx.gui.MDViewerPanel(markdown);
        viewer.setPreferredSize(size);
        if (modal) {
            JOptionPane.showMessageDialog(this, viewer, title, JOptionPane.PLAIN_MESSAGE);
            return;
        }
        Window owner = SwingUtilities.getWindowAncestor(this);
        JDialog dialog = new JDialog(owner, title, java.awt.Dialog.ModalityType.MODELESS);
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.getContentPane().add(viewer, BorderLayout.CENTER);
        dialog.pack();
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }

    private static JMenuItem item(String text, int mnemonic, KeyStroke accelerator, ActionListener action) {
        JMenuItem mi = new JMenuItem(text, mnemonic);
        if (accelerator != null)
            mi.setAccelerator(accelerator);
        mi.addActionListener(action);
        return mi;
    }

    // ------------------------------------------------------------------ EditorHost

    @Override
    public PDFViewerPanel viewer() {
        return viewer;
    }

    @Override
    public PDFEditModel model() {
        return model;
    }

    @Override
    public AnnotationStyle style(StyleKey key) {
        return styles.get(key);
    }

    @Override
    public JComponent dialogParent() {
        return this;
    }

    @Override
    public void toolDeactivated(PDFToolHandler tool) {
        if (activeTool != null && tools.get(activeTool) == tool) {
            activeTool = null;
            noTool.setSelected(true);
            updateStrip();
            updateButtons();
            changed();
        }
    }

    @Override
    public void annotationSelected(int page, PDAnnotation a) {
        selectedAnnotation = a;
        selectedPage = a == null ? -1 : page;
        updateStrip();
        updateButtons();
        changed();
    }

    @Override
    public void selectWithTool(int page, PDAnnotation a) {
        selectAnnotation(page, a);
    }

    // ------------------------------------------------------------------ internals

    private boolean applyEdit(PDFEdit edit) {
        if (!editable)
            setEditable(true);
        clearAnnotationSelection();
        try {
            model.apply(edit);
            return true;
        } catch (IOException | RuntimeException e) {
            showError(edit.name() + " failed: " + e.getMessage());
            return false;
        }
    }

    private void updateButtons() {
        undoButton.setEnabled(canUndo());
        redoButton.setEnabled(canRedo());
        PDFEdit u = model.peekUndo(), r = model.peekRedo();
        undoButton.setToolTipText((u == null ? "Undo" : "Undo: " + u.name())
                + " (Ctrl+Z). Saving over the open file clears the history.");
        redoButton.setToolTipText((r == null ? "Redo" : "Redo: " + r.name()) + " (Ctrl+Y)");
        boolean doc = viewer.getDocument() != null;
        for (JComponent c : editControls)
            c.setEnabled(editable && doc);
        if (editable && doc) {
            moveButton.setEnabled(viewer.getPageCount() > 1);
            deleteAnnotationButton.setEnabled(selectedAnnotation != null);
            propertiesButton.setEnabled(selectedAnnotation != null);
            boolean picture = selectedAnnotation != null && ImageStamp.isImage(selectedAnnotation);
            rotateLeftButton.setIcon(picture ? rotateImageLeftIcon : rotatePageLeftIcon);
            rotateRightButton.setIcon(picture ? rotateImageRightIcon : rotatePageRightIcon);
            rotateLeftButton.setToolTipText(picture ? ROTATE_IMAGE_LEFT_TIP : ROTATE_PAGE_LEFT_TIP);
            rotateRightButton.setToolTipText(picture ? ROTATE_IMAGE_RIGHT_TIP : ROTATE_PAGE_RIGHT_TIP);
            AnnotationStyle s = stripStyle();
            boolean image = imageStrip();
            strokeButton.setEnabled(s != null && !image);
            fillButton.setEnabled(s != null && !image);
            opacitySpinner.setEnabled(s != null);
            widthSpinner.setEnabled(s != null && !image);
            sizeSpinner.setEnabled(s != null && textStrip());
            fontCombo.setEnabled(s != null && textStrip());
            boldToggle.setEnabled(s != null && textStrip());
            italicToggle.setEnabled(s != null && textStrip());
            underlineToggle.setEnabled(s != null && textStrip());
            strikeToggle.setEnabled(s != null && textStrip());
            highlightButton.setEnabled(s != null && textStrip());
            alignCombo.setEnabled(s != null && textStrip());
            strokeButton.setToolTipText(textStrip() ? FONT_TIP : STROKE_TIP);
        }
    }

    private void changed() {
        updateButtons();
        ChangeEvent e = new ChangeEvent(this);
        for (ChangeListener l : listeners)
            l.stateChanged(e);
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    /** Routes the viewer's page edits through the model and answers its modified state. */
    private final class Delegate implements PDFViewerPanel.EditDelegate {
        @Override
        public boolean insertDocument(PDDocument source, int at) throws IOException {
            clearAnnotationSelection();
            model.apply(new InsertPagesEdit(viewer, source, at));
            return true;
        }

        @Override
        public boolean deletePages(int[] pages) {
            clearAnnotationSelection();
            try {
                model.apply(new DeletePagesEdit(viewer, pages));
            } catch (IOException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
            return true;
        }

        @Override
        public void documentReplaced() {
            model.reset();
            selectedAnnotation = null;
            selectedPage = -1;
            formTool().refresh(viewer.getToolContext());
            changed();
        }

        @Override
        public void documentSaved() {
            // PDFBox subsets an embedded font on the first save only: later text goes into fresh copies
            synchronized (viewer.getDocumentLock()) {
                EditorFonts.forget(viewer.getDocument());
            }
            model.markSaved();
            changed();
        }

        @Override
        public boolean isModified() {
            return model.isModified();
        }
    }
}
