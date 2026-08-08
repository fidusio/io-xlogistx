package io.xlogistx.gui;

import org.zoxweb.shared.util.SUS;

import java.awt.AWTException;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.image.BufferedImage;

/**
 * Immutable snapshot of a {@link SelectionArea}: the captured screen image plus
 * identification metadata (id, sequence number and capture timestamp).
 * <p>
 * Instances are value objects; use {@link #capture(String, long, SelectionArea)}
 * to grab the current screen content of a selection area.
 */
public class SnapShot {
    private final BufferedImage image;
    private final SelectionArea selectionArea;
    private final String id;
    private final long sequence;
    private final long timestamp;

    /**
     * Creates a snapshot stamped with the current time.
     *
     * @param id            identifier of the snapshot or its capture session, may be null
     * @param sequence      sequence number of the snapshot within its capture stream
     * @param selectionArea the selection area the image was captured from
     * @param image         the captured image
     * @throws NullPointerException if selectionArea or image is null
     */
    public SnapShot(String id, long sequence, SelectionArea selectionArea, BufferedImage image) {
        this(id, sequence, System.currentTimeMillis(), selectionArea, image);
    }

    /**
     * Creates a snapshot with an explicit timestamp.
     *
     * @param id            identifier of the snapshot or its capture session, may be null
     * @param sequence      sequence number of the snapshot within its capture stream
     * @param timestamp     capture time in epoch millis
     * @param selectionArea the selection area the image was captured from
     * @param image         the captured image
     * @throws NullPointerException if selectionArea or image is null
     */
    public SnapShot(String id, long sequence, long timestamp, SelectionArea selectionArea, BufferedImage image) {
        SUS.checkIfNulls("selectionArea or image can't be null", selectionArea, image);
        this.id = id;
        this.sequence = sequence;
        this.timestamp = timestamp;
        this.selectionArea = selectionArea;
        this.image = image;
    }

    /**
     * @return the captured image
     */
    public BufferedImage getImage() {
        return image;
    }

    /**
     * @return the selection area the image was captured from
     */
    public SelectionArea getSelectionArea() {
        return selectionArea;
    }

    /**
     * @return identifier of the snapshot or its capture session, may be null
     */
    public String getID() {
        return id;
    }

    /**
     * @return sequence number of the snapshot within its capture stream
     */
    public long getSequence() {
        return sequence;
    }

    /**
     * @return capture time in epoch millis
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Captures the current screen content of the given selection area and wraps it
     * in a SnapShot stamped with the current time. Creates a one-off {@link Robot};
     * for repeated captures prefer {@link #capture(String, long, SelectionArea, Robot)}
     * with a reused instance.
     *
     * @param id            identifier of the snapshot or its capture session, may be null
     * @param sequence      sequence number of the snapshot within its capture stream
     * @param selectionArea the selection area to capture, its rectangle must be set
     * @return the captured snapshot
     * @throws AWTException          if the platform does not allow screen capture
     * @throws IllegalStateException if the selection area has no rectangle set
     */
    public static SnapShot capture(String id, long sequence, SelectionArea selectionArea)
            throws AWTException {
        return capture(id, sequence, selectionArea, null);
    }

    /**
     * Captures the current screen content of the given selection area with the given
     * {@link Robot} and wraps it in a SnapShot stamped with the current time.
     *
     * @param id            identifier of the snapshot or its capture session, may be null
     * @param sequence      sequence number of the snapshot within its capture stream
     * @param selectionArea the selection area to capture, its rectangle must be set
     * @param robot         robot to capture with, null to create a one-off instance
     * @return the captured snapshot
     * @throws AWTException          if robot is null and the platform does not allow
     *                               screen capture
     * @throws IllegalStateException if the selection area has no rectangle set
     */
    public static SnapShot capture(String id, long sequence, SelectionArea selectionArea, Robot robot)
            throws AWTException {
        SUS.checkIfNulls("selectionArea can't be null", selectionArea);
        Rectangle area = selectionArea.getSelectionArea();
        if (area == null)
            throw new IllegalStateException("selection area rectangle not set: " + selectionArea.getName());
        return new SnapShot(id, sequence, selectionArea, GUIUtil.captureSelectedArea(area, robot));
    }

    @Override
    public String toString() {
        return "SnapShot{" +
                "id='" + id + '\'' +
                ", sequence=" + sequence +
                ", timestamp=" + timestamp +
                ", selectionArea=" + selectionArea.getName() +
                ", image=" + image.getWidth() + "x" + image.getHeight() +
                '}';
    }
}
