package io.xlogistx.editor.pdf;

import org.zoxweb.shared.util.SUS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;

/**
 * Several edits undone and redone as one step (e.g. a highlight spanning
 * pages, one annotation per page). Apply runs the parts in order, revert in
 * reverse; a part that fails on apply makes the already applied parts revert.
 */
public final class CompoundEdit implements PDFEdit {

    private final String name;
    private final List<PDFEdit> parts;

    /**
     * @param name  the step's name
     * @param parts the edits, in apply order; never null or empty
     */
    public CompoundEdit(String name, List<? extends PDFEdit> parts) {
        SUS.checkIfNull("parts null", parts);
        if (parts.isEmpty())
            throw new IllegalArgumentException("no edits");
        this.name = name == null ? parts.get(0).name() : name;
        this.parts = Collections.unmodifiableList(new ArrayList<>(parts));
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public void apply() throws IOException {
        int done = 0;
        try {
            for (PDFEdit e : parts) {
                e.apply();
                done++;
            }
        } catch (IOException | RuntimeException ex) {
            for (int i = done - 1; i >= 0; i--)
                parts.get(i).revert();
            throw ex;
        }
    }

    @Override
    public void revert() throws IOException {
        for (int i = parts.size() - 1; i >= 0; i--)
            parts.get(i).revert();
    }

    @Override
    public int[] affectedPages() {
        TreeSet<Integer> set = new TreeSet<>();
        for (PDFEdit e : parts)
            for (int p : e.affectedPages())
                set.add(p);
        int[] ret = new int[set.size()];
        int i = 0;
        for (int p : set)
            ret[i++] = p;
        return ret;
    }

    @Override
    public boolean structural() {
        for (PDFEdit e : parts)
            if (e.structural())
                return true;
        return false;
    }

    /** @return the parts, in apply order */
    public List<PDFEdit> getParts() {
        return parts;
    }
}
