package io.xlogistx.gui;

import org.zoxweb.server.io.UByteArrayInputStream;
import org.zoxweb.server.util.UUID7;
import org.zoxweb.shared.util.CollectionAsArray;

import java.awt.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Ordered set of {@link CaptureArea}s with on-demand capture:
 * {@link #takeSnapShots(CaptureArea...)} grabs the current screen content of the
 * given areas (or every area in the set when called without arguments) and returns
 * the result as {@link SnapShot}s.
 * <p>
 * Reads go through a lock-free copy-on-write snapshot ({@link CollectionAsArray}),
 * so {@link #getCaptureAreas()} is safe while another thread mutates the set.
 */
public class CaptureAreaSet {
    private final CollectionAsArray<CaptureArea> captureAreas = new CollectionAsArray<>(new LinkedHashSet<>(), new CaptureArea[0]);
    private final AtomicLong sequence = new AtomicLong();
    private volatile Robot cachedRobot;

    public CaptureAreaSet() {
    }

    /**
     * @return snapshot of the areas in insertion order; shared and read-only, never null
     */
    public CaptureArea[] getCaptureAreas() {
        return captureAreas.asArray();
    }

    /**
     * Adds the given areas at the end of the set; an area already present
     * (same instance) is not duplicated.
     *
     * @param captureArea areas to add
     * @return this instance, for fluent chaining
     */
    public CaptureAreaSet addCaptureAreas(CaptureArea... captureArea) {
        captureAreas.add(captureArea);
        return this;
    }

    /**
     * Removes the given areas from the set; areas not present are ignored.
     *
     * @param captureArea areas to remove
     * @return this instance, for fluent chaining
     */
    public CaptureAreaSet removeCaptureAreas(CaptureArea... captureArea) {
        captureAreas.remove(captureArea);
        return this;
    }

    /**
     * Removes all areas from the set.
     *
     * @return this instance, for fluent chaining
     */
    public CaptureAreaSet clearCaptureAreas() {
        captureAreas.clear();
        return this;
    }

    /**
     * Removes the area at the given position in insertion order; out-of-range
     * indexes are ignored.
     *
     * @param index zero-based position of the area to remove
     * @return this instance, for fluent chaining
     */
    public CaptureAreaSet removeCaptureAreaAtIndex(int index) {
        CaptureArea[] areas = getCaptureAreas();
        if (index >= 0 && index < areas.length) {
            return removeCaptureAreas(areas[index]);
        }
        return this;
    }

    /**
     * Captures the current screen content of the given areas in one sweep; no areas
     * (or null) means every area in the set. Areas that are null or whose rectangle
     * is unset or empty (click without drag) are skipped. Each snapshot carries a
     * unique UUID as id, its area's name as source id, and a sequence number that
     * increments per snapshot across the lifetime of this set.
     *
     * @param captureAreas the areas to capture, empty or null for all areas in the set
     * @return one snapshot per capturable area, in the order given
     * @throws IllegalStateException if the platform does not allow screen capture
     */
    public SnapShot[] takeSnapShots(CaptureArea... captureAreas) {
        List<SnapShot> ret = new ArrayList<>();
        if (captureAreas == null || captureAreas.length == 0)
            captureAreas = getCaptureAreas();

        if (captureAreas.length > 0) {
            Robot robot = robot();
            // Robot is not documented as thread-safe: serialize concurrent sweeps on it
            synchronized (robot) {
                for (CaptureArea captureArea : captureAreas) {
                    if (captureArea == null)
                        continue;
                    Rectangle area = captureArea.getCaptureArea();
                    if (area == null || area.isEmpty())
                        continue;
                    try {
                        ret.add(captureArea.takeSnapShot(UUID7.randomUUID().toString(), sequence.getAndIncrement(), robot));
                    } catch (AWTException e) {
                        // unreachable: AWTException is only thrown when capture must
                        // create its own Robot, and we always pass the cached one
                        throw new IllegalStateException("screen capture failed", e);
                    }
                }
            }
        }
        return ret.toArray(new SnapShot[0]);
    }

    /**
     * Captures the given areas in one sweep and encodes each snapshot in the given
     * format; no areas (or null) means the whole set, matching
     * {@link #takeSnapShots(CaptureArea...)}.
     * <p>
     * The result carries the image bytes only — no area name, sequence or timestamp —
     * and may be shorter than the input since unset/empty rectangles are skipped, so
     * result indexes do NOT align with the areas passed in. Callers that need to know
     * which image belongs to which area should use {@link #takeSnapShots(CaptureArea...)}
     * and {@link SnapShot#exportAsInputStream(String)} instead.
     *
     * @param format       image format name, case-insensitive (e.g. "png", "jpg");
     *                     jpg is encoded at {@link GUIUtil#DEFAULT_JPG_QUALITY}
     * @param captureAreas the areas to capture, empty or null for all areas in the set
     * @return one encoded image per capturable area, in capture order
     * @throws IOException           if the format is unsupported or encoding fails;
     *                               the sweep's captures are discarded
     * @throws IllegalStateException if the platform does not allow screen capture
     */
    public UByteArrayInputStream[] exportAsInputStreams(String format, CaptureArea... captureAreas) throws IOException {
        SnapShot[] snapShots = takeSnapShots(captureAreas);
        UByteArrayInputStream[] ret = new UByteArrayInputStream[snapShots.length];
        for (int i = 0; i < snapShots.length; i++) {
            ret[i] = snapShots[i].exportAsInputStream(format);
        }
        return ret;
    }

    /**
     * Lazily creates and caches the {@link Robot} via double-checked locking (the
     * field is volatile, making the pattern safe); it stays valid for the life of
     * the process and keeps capturing the default screen device it was created for.
     *
     * @return the cached robot
     * @throws IllegalStateException if the platform does not allow screen capture
     */
    private Robot robot() {
        if (cachedRobot == null) {
            synchronized (this) {
                // re-check under the lock: another thread may have won the race
                if (cachedRobot == null) {
                    try {
                        cachedRobot = new Robot();
                    } catch (AWTException e) {
                        throw new IllegalStateException("screen capture not available", e);
                    }
                }
            }
        }
        return cachedRobot;
    }
}
