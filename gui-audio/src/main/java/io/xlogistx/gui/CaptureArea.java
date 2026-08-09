package io.xlogistx.gui;

import org.zoxweb.shared.util.NamedDescription;
import org.zoxweb.shared.util.SetDescription;
import org.zoxweb.shared.util.SetName;

import java.awt.*;

/**
 * A named rectangular region of the screen, the unit of capture used by
 * {@link CaptureAreaSet} and {@link SnapShot}.
 * <p>
 * The rectangle is typically produced by {@link GUIUtil#captureSelectedArea()}
 * (drag selection) and may be null until set, or empty when the user clicked
 * without dragging — consumers must handle both. The field is volatile so the
 * rectangle can be swapped while capture sweeps read it from another thread.
 */
public class CaptureArea
    implements SetName, SetDescription {

    private NamedDescription namedDescription;
    private volatile Rectangle captureArea;


    /**
     * Creates an unnamed area with no rectangle; populate via the setters.
     */
    public CaptureArea() {
        namedDescription = new NamedDescription();
    }

    /**
     * Creates a fully populated area.
     *
     * @param name        name of the area, used as the {@link SnapShot} source id
     * @param description optional description, may be null
     * @param captureArea screen rectangle to capture, may be null until selected
     */
    public CaptureArea(String name, String description, Rectangle captureArea) {
        this();
        setName(name);
        setDescription(description);
        this.captureArea = captureArea;
    }

    /**
     * @return the screen rectangle to capture; null if not selected yet, may be
     *         empty (click without drag)
     */
    public Rectangle getCaptureArea() {
        return captureArea;
    }

    /**
     * Sets the screen rectangle to capture.
     *
     * @param selectedArea the new rectangle, in screen coordinates
     * @return this instance, for fluent chaining
     */
    public CaptureArea setCaptureArea(Rectangle selectedArea) {
        captureArea = selectedArea;
        return this;
    }

    /**
     * Set description property.
     *
     * @param str the description, may be null
     */
    @Override
    public void setDescription(String str) {
        namedDescription.setDescription(str);
    }

    /**
     * Returns the property description.
     *
     * @return description
     */
    @Override
    public String getDescription() {
        return namedDescription.getDescription();
    }

    /**
     * Set name property.
     *
     * @param name the name of the area
     */
    @Override
    public void setName(String name) {
        namedDescription.setName(name);
    }

    /**
     * @return the name of the object
     */
    @Override
    public String getName() {
        return namedDescription.getName();
    }


    /**
     * Captures the current screen content of this area and wraps it in a
     * {@link SnapShot} stamped with the current time. Creates a one-off
     * {@link Robot}; for repeated captures prefer
     * {@link #takeSnapShot(String, long, Robot)} with a reused instance.
     *
     * @param id       identifier of the snapshot or its capture session, may be null
     * @param sequence sequence number of the snapshot within its capture stream
     * @return the captured snapshot, its source id set to this area's name
     * @throws AWTException          if the platform does not allow screen capture
     * @throws IllegalStateException if this area has no rectangle set
     */
    public SnapShot takeSnapShot(String id, long sequence)
            throws AWTException {
        return takeSnapShot(id, sequence, null);
    }

    /**
     * Captures the current screen content of this area with the given {@link Robot}
     * and wraps it in a {@link SnapShot} stamped with the current time.
     *
     * @param id       identifier of the snapshot or its capture session, may be null
     * @param sequence sequence number of the snapshot within its capture stream
     * @param robot    robot to capture with, null to create a one-off instance
     * @return the captured snapshot, its source id set to this area's name
     * @throws AWTException          if robot is null and the platform does not allow
     *                               screen capture
     * @throws IllegalStateException if this area has no rectangle set
     */
    public SnapShot takeSnapShot(String id, long sequence, Robot robot)
            throws AWTException {
        Rectangle area = getCaptureArea();
        if (area == null)
            throw new IllegalStateException("capture area rectangle not set: " + getName());
        return new SnapShot(id, sequence, getName(), GUIUtil.captureSelectedArea(area, robot));
    }
}
