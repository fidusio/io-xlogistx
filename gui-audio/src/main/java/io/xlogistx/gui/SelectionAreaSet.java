package io.xlogistx.gui;

import org.zoxweb.shared.util.CollectionAsArray;

import java.awt.AWTException;
import java.awt.Rectangle;
import java.awt.Robot;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Ordered set of {@link SelectionArea}s with on-demand capture: {@link #snapShots()}
 * grabs the current screen content of every area and returns the result as
 * {@link SnapShot}s.
 * <p>
 * Reads go through a lock-free copy-on-write snapshot ({@link CollectionAsArray}),
 * so {@link #getSelectionAreas()} is safe while another thread mutates the set.
 */
public class SelectionAreaSet {
    private final CollectionAsArray<SelectionArea> selectionAreas = new CollectionAsArray<>(new LinkedHashSet<>(), new SelectionArea[0]);
    private final AtomicLong sequence = new AtomicLong();
    private volatile Robot robot;

    public SelectionAreaSet() {
    }

    /**
     * @return snapshot of the areas in insertion order; shared and read-only, never null
     */
    public SelectionArea[] getSelectionAreas() {
        return selectionAreas.asArray();
    }

    /**
     * Adds the given areas at the end of the set; an area already present
     * (same instance) is not duplicated.
     *
     * @param selectionArea areas to add
     * @return this instance, for fluent chaining
     */
    public SelectionAreaSet addSelectionArea(SelectionArea... selectionArea) {
        selectionAreas.add(selectionArea);
        return this;
    }

    /**
     * Removes the given areas from the set; areas not present are ignored.
     *
     * @param selectionArea areas to remove
     * @return this instance, for fluent chaining
     */
    public SelectionAreaSet removeSelectionAreas(SelectionArea... selectionArea) {
        selectionAreas.remove(selectionArea);
        return this;
    }

    /**
     * Removes all areas from the set.
     *
     * @return this instance, for fluent chaining
     */
    public SelectionAreaSet clearSelectionAreas() {
        selectionAreas.clear();
        return this;
    }

    /**
     * Removes the area at the given position in insertion order; out-of-range
     * indexes are ignored.
     *
     * @param index zero-based position of the area to remove
     * @return this instance, for fluent chaining
     */
    public SelectionAreaSet removeSelectionAreaAtIndex(int index) {
        SelectionArea[] areas = getSelectionAreas();
        if (index >= 0 && index < areas.length) {
            return removeSelectionAreas(areas[index]);
        }
        return this;
    }

    /**
     * Captures the current screen content of every area in the set.
     *
     * @return one snapshot per capturable area, in insertion order
     * @throws IllegalStateException if the platform does not allow screen capture
     */
    public SnapShot[] snapShots() {
        return snapShots(selectionAreas.asArray());
    }

    /**
     * Captures the current screen content of the given areas in one sweep. Areas
     * that are null or whose rectangle is unset or empty (click without drag) are
     * skipped. All snapshots carry their area's name as id and a sequence number
     * that increments per snapshot across the lifetime of this set.
     *
     * @param selectionAreas the areas to capture
     * @return one snapshot per capturable area, in the order given
     * @throws IllegalStateException if the platform does not allow screen capture
     */
    public SnapShot[] snapShots(SelectionArea... selectionAreas) {
        Robot robot = robot();
        List<SnapShot> ret = new ArrayList<>();
        // Robot is not documented as thread-safe: serialize concurrent sweeps on it
        synchronized (robot) {
            for (SelectionArea selectionArea : selectionAreas) {
                if (selectionArea == null)
                    continue;
                Rectangle area = selectionArea.getSelectionArea();
                if (area == null || area.isEmpty())
                    continue;
                try {
                    ret.add(SnapShot.capture(selectionArea.getName(), sequence.getAndIncrement(),
                            selectionArea, robot));
                } catch (AWTException e) {
                    // unreachable: AWTException is only thrown when capture must
                    // create its own Robot, and we always pass the cached one
                    throw new IllegalStateException("screen capture failed", e);
                }
            }
        }
        return ret.toArray(new SnapShot[0]);
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
        if (robot == null) {
            synchronized (this) {
                // re-check under the lock: another thread may have won the race
                if (robot == null) {
                    try {
                        robot = new Robot();
                    } catch (AWTException e) {
                        throw new IllegalStateException("screen capture not available", e);
                    }
                }
            }
        }
        return robot;
    }
}
