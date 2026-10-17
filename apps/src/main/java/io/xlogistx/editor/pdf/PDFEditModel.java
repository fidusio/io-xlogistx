package io.xlogistx.editor.pdf;

import org.zoxweb.shared.util.SUS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Bounded undo/redo stacks of {@link PDFEdit}s plus the modified flag of the
 * document they belong to. Pure Java: nothing here touches Swing or PDFBox, the
 * edits do. Not thread-safe; the owning pane calls it on the EDT only.
 * <p>
 * The modified flag is positional: the model remembers the undo depth at the
 * last {@link #markSaved()} and reports unmodified whenever the stack is back
 * at that depth, so undoing to the saved state clears the asterisk again. When
 * the saved state falls off the bottom of the bounded stack it can never be
 * reached again and the document stays modified.
 */
public final class PDFEditModel {

    /** Most edits kept; the oldest is dropped beyond it. */
    public static final int MAX_UNDO = 100;

    /** Notified after every apply, undo and redo. */
    @FunctionalInterface
    public interface Listener {
        /**
         * @param model the model
         * @param edit  the edit that was applied or reverted
         * @param undo  true when the edit was reverted, false when applied (first time or redo)
         */
        void edited(PDFEditModel model, PDFEdit edit, boolean undo);
    }

    private final List<PDFEdit> undoStack = new ArrayList<>();
    private final List<PDFEdit> redoStack = new ArrayList<>();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    /** Undo depth at the last save; -1 when the saved state was dropped from the stack. */
    private int savedDepth;

    /**
     * Applies an edit and records it; the redo history is discarded.
     *
     * @param edit the edit, never null
     * @throws IOException if the edit fails (nothing is recorded then)
     */
    public void apply(PDFEdit edit) throws IOException {
        SUS.checkIfNull("edit null", edit);
        edit.apply();
        undoStack.add(edit);
        redoStack.clear();
        if (undoStack.size() > MAX_UNDO) {
            undoStack.remove(0);
            savedDepth = savedDepth > 0 ? savedDepth - 1 : -1;
        }
        fire(edit, false);
    }

    /** @return whether {@link #undo()} has something to revert */
    public boolean canUndo() {
        return !undoStack.isEmpty();
    }

    /** @return whether {@link #redo()} has something to re-apply */
    public boolean canRedo() {
        return !redoStack.isEmpty();
    }

    /**
     * Reverts the most recent edit.
     *
     * @return the reverted edit, null when there was none
     * @throws IOException if the edit fails to revert; it stays on the undo stack
     */
    public PDFEdit undo() throws IOException {
        if (undoStack.isEmpty())
            return null;
        PDFEdit edit = undoStack.get(undoStack.size() - 1);
        edit.revert();
        undoStack.remove(undoStack.size() - 1);
        redoStack.add(edit);
        fire(edit, true);
        return edit;
    }

    /**
     * Re-applies the most recently undone edit.
     *
     * @return the re-applied edit, null when there was none
     * @throws IOException if the edit fails to apply; it stays on the redo stack
     */
    public PDFEdit redo() throws IOException {
        if (redoStack.isEmpty())
            return null;
        PDFEdit edit = redoStack.get(redoStack.size() - 1);
        edit.apply();
        redoStack.remove(redoStack.size() - 1);
        undoStack.add(edit);
        fire(edit, false);
        return edit;
    }

    /** @return the edit {@link #undo()} would revert, null when none */
    public PDFEdit peekUndo() {
        return undoStack.isEmpty() ? null : undoStack.get(undoStack.size() - 1);
    }

    /** @return the edit {@link #redo()} would re-apply, null when none */
    public PDFEdit peekRedo() {
        return redoStack.isEmpty() ? null : redoStack.get(redoStack.size() - 1);
    }

    /** @return true when the document differs from its last saved (or initial) state */
    public boolean isModified() {
        return undoStack.size() != savedDepth;
    }

    /** The document was written out: the current state is the clean one; the stacks are kept. */
    public void markSaved() {
        savedDepth = undoStack.size();
    }

    /** A new document was loaded (or none): both stacks are cleared and the state is clean. */
    public void reset() {
        undoStack.clear();
        redoStack.clear();
        savedDepth = 0;
    }

    /** @return number of edits that can be undone */
    public int getUndoDepth() {
        return undoStack.size();
    }

    /** @return number of edits that can be redone */
    public int getRedoDepth() {
        return redoStack.size();
    }

    /** @param l the listener to add, never null */
    public void addListener(Listener l) {
        SUS.checkIfNull("listener null", l);
        listeners.add(l);
    }

    /** @param l the listener to remove */
    public void removeListener(Listener l) {
        listeners.remove(l);
    }

    private void fire(PDFEdit edit, boolean undo) {
        for (Listener l : listeners)
            l.edited(this, edit, undo);
    }
}
