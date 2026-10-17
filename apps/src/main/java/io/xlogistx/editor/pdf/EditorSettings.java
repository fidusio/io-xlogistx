package io.xlogistx.editor.pdf;

import org.zoxweb.shared.util.SUS;

import java.awt.Rectangle;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

/**
 * What the editor remembers between runs, on a {@link Preferences} node: the
 * recent files (most recent first, at most {@link #MAX_RECENT}), the last
 * directory a file was opened from or saved to, whether the thumbnail sidebar
 * is shown, the zoom, and the window's bounds. {@link #user()} is the real
 * store (the user's node for this package); tests hand in a throwaway node.
 */
public final class EditorSettings {

    /** How many recent files are kept. */
    public static final int MAX_RECENT = 10;

    private static final String RECENT = "recent.", LAST_DIR = "last.dir", THUMBNAILS = "thumbnails",
            ZOOM_MODE = "zoom.mode", ZOOM = "zoom", WINDOW_X = "window.x", WINDOW_Y = "window.y",
            WINDOW_W = "window.w", WINDOW_H = "window.h", WINDOW_MAX = "window.max", UI_FONT_SIZE = "ui.font.size";

    private final Preferences prefs;

    /**
     * @param prefs the node the settings live on, never null
     */
    public EditorSettings(Preferences prefs) {
        SUS.checkIfNull("preferences null", prefs);
        this.prefs = prefs;
    }

    /** @return the settings on the user's node for this package */
    public static EditorSettings user() {
        return new EditorSettings(Preferences.userNodeForPackage(EditorSettings.class));
    }

    /** @return the node the settings live on */
    public Preferences node() {
        return prefs;
    }

    // ------------------------------------------------------------------ recent files

    /** @return the recent files, most recent first; the files may no longer exist */
    public List<File> getRecentFiles() {
        List<File> r = new ArrayList<>();
        for (int i = 0; i < MAX_RECENT; i++) {
            String path = prefs.get(RECENT + i, null);
            if (path == null || path.trim().isEmpty())
                continue;
            r.add(new File(path));
        }
        return r;
    }

    /**
     * Puts a file at the front of the recent list (removing an older entry of
     * the same file) and drops the oldest beyond {@link #MAX_RECENT}.
     */
    public void addRecentFile(File file) {
        SUS.checkIfNull("file null", file);
        File f = file.getAbsoluteFile();
        List<File> r = getRecentFiles();
        r.removeIf(x -> x.getAbsoluteFile().equals(f));
        r.add(0, f);
        while (r.size() > MAX_RECENT)
            r.remove(r.size() - 1);
        writeRecent(r);
    }

    /** Removes a file from the recent list (a file that no longer exists, say). */
    public void removeRecentFile(File file) {
        SUS.checkIfNull("file null", file);
        File f = file.getAbsoluteFile();
        List<File> r = getRecentFiles();
        if (r.removeIf(x -> x.getAbsoluteFile().equals(f)))
            writeRecent(r);
    }

    /** Empties the recent list. */
    public void clearRecentFiles() {
        writeRecent(new ArrayList<>());
    }

    private void writeRecent(List<File> r) {
        for (int i = 0; i < MAX_RECENT; i++) {
            if (i < r.size())
                prefs.put(RECENT + i, r.get(i).getAbsolutePath());
            else
                prefs.remove(RECENT + i);
        }
    }

    // ------------------------------------------------------------------ the rest

    /** @return the directory file dialogs start in, null when none was recorded or it is gone */
    public File getLastDirectory() {
        String d = prefs.get(LAST_DIR, null);
        if (d == null)
            return null;
        File dir = new File(d);
        return dir.isDirectory() ? dir : null;
    }

    /** @param dir the directory file dialogs start in, null forgets it */
    public void setLastDirectory(File dir) {
        if (dir == null)
            prefs.remove(LAST_DIR);
        else
            prefs.put(LAST_DIR, dir.getAbsolutePath());
    }

    /** @return whether the thumbnail sidebar is shown (false until set) */
    public boolean isThumbnailsVisible() {
        return prefs.getBoolean(THUMBNAILS, false);
    }

    public void setThumbnailsVisible(boolean visible) {
        prefs.putBoolean(THUMBNAILS, visible);
    }

    /** @return the zoom mode's name (a {@code PDFViewerPanel.ZoomMode}), null until set */
    public String getZoomMode() {
        return prefs.get(ZOOM_MODE, null);
    }

    public void setZoomMode(String mode) {
        if (mode == null)
            prefs.remove(ZOOM_MODE);
        else
            prefs.put(ZOOM_MODE, mode);
    }

    /** @return the zoom factor for the custom mode, {@code fallback} until set */
    public float getZoom(float fallback) {
        return prefs.getFloat(ZOOM, fallback);
    }

    public void setZoom(float zoom) {
        prefs.putFloat(ZOOM, zoom);
    }

    /** @return the window's bounds, null until set */
    public Rectangle getWindowBounds() {
        int w = prefs.getInt(WINDOW_W, -1), h = prefs.getInt(WINDOW_H, -1);
        if (w <= 0 || h <= 0)
            return null;
        return new Rectangle(prefs.getInt(WINDOW_X, 0), prefs.getInt(WINDOW_Y, 0), w, h);
    }

    public void setWindowBounds(Rectangle r) {
        if (r == null) {
            for (String k : new String[]{WINDOW_X, WINDOW_Y, WINDOW_W, WINDOW_H})
                prefs.remove(k);
            return;
        }
        prefs.putInt(WINDOW_X, r.x);
        prefs.putInt(WINDOW_Y, r.y);
        prefs.putInt(WINDOW_W, r.width);
        prefs.putInt(WINDOW_H, r.height);
    }

    /** @return whether the window was maximized (false until set) */
    public boolean isWindowMaximized() {
        return prefs.getBoolean(WINDOW_MAX, false);
    }

    public void setWindowMaximized(boolean maximized) {
        prefs.putBoolean(WINDOW_MAX, maximized);
    }

    /** @return the control text size in points (see {@code io.xlogistx.gui.UIFontSize}), {@code fallback} until set */
    public float getUIFontSize(float fallback) {
        return prefs.getFloat(UI_FONT_SIZE, fallback);
    }

    public void setUIFontSize(float size) {
        prefs.putFloat(UI_FONT_SIZE, size);
    }

    /** Pushes the settings to the backing store; failures are ignored (the values stay in memory). */
    public void flush() {
        try {
            prefs.flush();
        } catch (BackingStoreException e) {
            // the store is unavailable: nothing to do, the next run starts from the defaults
        }
    }
}
