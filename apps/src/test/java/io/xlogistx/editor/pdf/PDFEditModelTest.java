package io.xlogistx.editor.pdf;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** {@link PDFEditModel} with recording edits; no document involved. */
public class PDFEditModelTest {

    /** Appends "+name" on apply and "-name" on revert to a shared log. */
    private static final class Recording implements PDFEdit {
        final String id;
        final List<String> log;
        boolean failApply, failRevert;

        Recording(String id, List<String> log) {
            this.id = id;
            this.log = log;
        }

        @Override
        public String name() {
            return "edit " + id;
        }

        @Override
        public void apply() throws IOException {
            if (failApply)
                throw new IOException("apply " + id);
            log.add("+" + id);
        }

        @Override
        public void revert() throws IOException {
            if (failRevert)
                throw new IOException("revert " + id);
            log.add("-" + id);
        }

        @Override
        public int[] affectedPages() {
            return new int[0];
        }

        @Override
        public boolean structural() {
            return false;
        }
    }

    @Test
    void appliesUndoesAndRedoesInOrder() throws Exception {
        List<String> log = new ArrayList<>();
        PDFEditModel m = new PDFEditModel();
        List<String> events = new ArrayList<>();
        m.addListener((model, edit, undo) -> events.add((undo ? "undo " : "apply ") + edit.name()));
        assertFalse(m.canUndo());
        assertFalse(m.canRedo());
        assertNull(m.undo());
        assertNull(m.redo());

        Recording a = new Recording("a", log), b = new Recording("b", log);
        m.apply(a);
        m.apply(b);
        assertEquals(Arrays.asList("+a", "+b"), log);
        assertEquals(2, m.getUndoDepth());
        assertSame(b, m.peekUndo());
        assertNull(m.peekRedo());

        assertSame(b, m.undo());
        assertEquals(Arrays.asList("+a", "+b", "-b"), log);
        assertSame(b, m.peekRedo());
        assertSame(a, m.peekUndo());
        assertSame(b, m.redo());
        assertEquals(Arrays.asList("+a", "+b", "-b", "+b"), log);
        assertSame(b, m.undo());
        assertSame(a, m.undo());
        assertFalse(m.canUndo());
        assertEquals(2, m.getRedoDepth());
        assertEquals(Arrays.asList("apply edit a", "apply edit b", "undo edit b", "apply edit b", "undo edit b", "undo edit a"), events);
    }

    @Test
    void newApplyClearsRedo() throws Exception {
        List<String> log = new ArrayList<>();
        PDFEditModel m = new PDFEditModel();
        m.apply(new Recording("a", log));
        m.undo();
        assertTrue(m.canRedo());
        m.apply(new Recording("b", log));
        assertFalse(m.canRedo());
        assertEquals(1, m.getUndoDepth());
    }

    @Test
    void failedApplyRecordsNothingAndFailedUndoKeepsTheEdit() throws Exception {
        List<String> log = new ArrayList<>();
        PDFEditModel m = new PDFEditModel();
        Recording bad = new Recording("bad", log);
        bad.failApply = true;
        assertThrows(IOException.class, () -> m.apply(bad));
        assertFalse(m.canUndo());
        assertFalse(m.isModified());

        Recording stuck = new Recording("stuck", log);
        m.apply(stuck);
        stuck.failRevert = true;
        assertThrows(IOException.class, m::undo);
        assertTrue(m.canUndo());
        assertSame(stuck, m.peekUndo());
        assertFalse(m.canRedo());
    }

    @Test
    void modifiedIsPositionalAroundTheSavedState() throws Exception {
        List<String> log = new ArrayList<>();
        PDFEditModel m = new PDFEditModel();
        assertFalse(m.isModified());
        m.apply(new Recording("a", log));
        assertTrue(m.isModified());
        m.undo();
        assertFalse(m.isModified(), "back at the initial state");
        m.redo();
        assertTrue(m.isModified());
        m.markSaved();
        assertFalse(m.isModified());
        assertTrue(m.canUndo(), "saving keeps the history");
        m.undo();
        assertTrue(m.isModified(), "before the saved state");
        m.redo();
        assertFalse(m.isModified());
        m.apply(new Recording("b", log));
        assertTrue(m.isModified());
        m.undo();
        assertFalse(m.isModified());
        m.reset();
        assertFalse(m.canUndo());
        assertFalse(m.canRedo());
        assertFalse(m.isModified());
    }

    @Test
    void stackIsBoundedAndADroppedSavedStateStaysModified() throws Exception {
        List<String> log = new ArrayList<>();
        PDFEditModel m = new PDFEditModel();
        m.apply(new Recording("first", log));
        m.markSaved();
        for (int i = 0; i < PDFEditModel.MAX_UNDO; i++)
            m.apply(new Recording("e" + i, log));
        assertEquals(PDFEditModel.MAX_UNDO, m.getUndoDepth());
        assertTrue(m.isModified());
        for (int i = 0; i < PDFEditModel.MAX_UNDO; i++)
            m.undo();
        assertFalse(m.canUndo(), "'first' was dropped");
        assertFalse(m.isModified(), "the state below the stack bottom is the saved one (after 'first')");

        // saved at the initial state, then that state falls off the bottom: never clean again
        PDFEditModel n = new PDFEditModel();
        for (int i = 0; i < PDFEditModel.MAX_UNDO + 5; i++)
            n.apply(new Recording("x" + i, log));
        assertEquals(PDFEditModel.MAX_UNDO, n.getUndoDepth());
        assertEquals("edit x" + (PDFEditModel.MAX_UNDO + 4), n.peekUndo().name());
        while (n.canUndo())
            n.undo();
        assertTrue(n.isModified(), "the initial state cannot be reached any more");
    }

    @Test
    void rejectsNulls() {
        PDFEditModel m = new PDFEditModel();
        assertThrows(NullPointerException.class, () -> m.apply(null));
        assertThrows(NullPointerException.class, () -> m.addListener(null));
    }
}
