package io.xlogistx.gui;

import org.zoxweb.shared.util.NamedDescription;
import org.zoxweb.shared.util.SetDescription;
import org.zoxweb.shared.util.SetName;

import java.awt.*;

/**
 * A named rectangular region of the screen, the unit of capture used by
 * {@link CaptureAreaSet} and {@link SnapShot}. Each area owns its capture
 * {@link Robot}, lazily created and bound to a {@link GraphicsDevice} — the
 * monitor the area lives on, resolved automatically from the rectangle via
 * {@link GUIUtil#deviceForArea(Rectangle)} whenever the rectangle is set;
 * {@link #setGraphicsDevice(GraphicsDevice)} overrides it.
 * <p>
 * The rectangle is typically produced by {@link GUIUtil#captureSelectedArea()}
 * (drag selection) and may be null until set, or empty when the user clicked
 * without dragging — consumers must handle both. The fields are volatile so they
 * can be swapped while capture sweeps read them from another thread.
 */
public class CaptureArea
    implements SetName, SetDescription {

    private NamedDescription namedDescription;
    private volatile Rectangle captureArea;
    private volatile GraphicsDevice graphicsDevice;
    private volatile Robot robot;


    /**
     * Creates an unnamed area with no rectangle; populate via the setters.
     */
    public CaptureArea() {
        namedDescription = new NamedDescription();
    }

    /**
     * Creates a fully populated area; the screen device is resolved automatically
     * from the rectangle, see {@link #setCaptureArea(Rectangle)}.
     *
     * @param name        name of the area, used as the {@link SnapShot} source id
     * @param description optional description, may be null
     * @param captureArea screen rectangle to capture, may be null until selected
     */
    public CaptureArea(String name, String description, Rectangle captureArea) {
        this();
        setName(name);
        setDescription(description);
        setCaptureArea(captureArea);
    }

    /**
     * Creates a fully populated area capturing from the given screen device, see
     * {@link #setGraphicsDevice(GraphicsDevice)}.
     *
     * @param name           name of the area, used as the {@link SnapShot} source id
     * @param description    optional description, may be null
     * @param captureArea    screen rectangle to capture, may be null until selected
     * @param graphicsDevice the screen device to capture from, null to keep the one
     *                       auto-resolved from the rectangle
     * @throws IllegalArgumentException if the device is not a screen device
     */
    public CaptureArea(String name, String description, Rectangle captureArea, GraphicsDevice graphicsDevice) {
        this(name, description, captureArea);
        if (graphicsDevice != null)
            setGraphicsDevice(graphicsDevice);
    }

    /**
     * @return the screen device captures are bound to; null means the default device
     */
    public GraphicsDevice getGraphicsDevice() {
        return graphicsDevice;
    }

    /**
     * Overrides the auto-resolved screen device the capture {@link Robot} is bound
     * to and discards the cached robot so the next capture rebinds; setting the
     * rectangle again re-resolves the device, see {@link #setCaptureArea(Rectangle)}.
     * On platforms with a virtual device configuration (e.g. Windows multi-monitor)
     * the rectangle remains in virtual-screen coordinates regardless of the device,
     * so the default device captures any monitor; binding mainly matters on
     * platforms with independent screens.
     *
     * @param graphicsDevice the screen device to capture from, null for the default
     * @return this instance, for fluent chaining
     * @throws IllegalArgumentException if the device is not a screen device
     */
    public CaptureArea setGraphicsDevice(GraphicsDevice graphicsDevice) {
        if (graphicsDevice != null && graphicsDevice.getType() != GraphicsDevice.TYPE_RASTER_SCREEN)
            throw new IllegalArgumentException("not a screen device: " + graphicsDevice.getIDstring());
        synchronized (this) {
            this.graphicsDevice = graphicsDevice;
            robot = null;
        }
        return this;
    }

    /**
     * @return the screen rectangle to capture; null if not selected yet, may be
     *         empty (click without drag)
     */
    public Rectangle getCaptureArea() {
        return captureArea;
    }

    /**
     * Sets the screen rectangle to capture and re-resolves the screen device to the
     * monitor holding it (via {@link GUIUtil#deviceForArea(Rectangle)}), discarding
     * the cached {@link Robot} so the next capture rebinds. The device is null —
     * default robot — when the rectangle is null, lies outside every monitor, or
     * the environment is headless; a subsequent
     * {@link #setGraphicsDevice(GraphicsDevice)} overrides the resolved device.
     *
     * @param selectedArea the new rectangle, in screen coordinates
     * @return this instance, for fluent chaining
     */
    public CaptureArea setCaptureArea(Rectangle selectedArea) {
        synchronized (this) {
            captureArea = selectedArea;
            graphicsDevice = selectedArea == null || GraphicsEnvironment.isHeadless()
                    ? null : GUIUtil.deviceForArea(selectedArea);
            robot = null;
        }
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
     * Captures the current screen content of this area with its own {@link Robot}
     * and wraps it in a {@link SnapShot} stamped with the current time. Concurrent
     * captures of the same area are serialized on the robot, which is not
     * documented as thread-safe.
     *
     * @param id       identifier of the snapshot or its capture session, may be null
     * @param sequence sequence number of the snapshot within its capture stream
     * @return the captured snapshot, its source id set to this area's name
     * @throws AWTException          if the platform does not allow screen capture
     * @throws IllegalStateException if this area has no rectangle set
     */
    public SnapShot takeSnapShot(String id, long sequence)
            throws AWTException {
        Rectangle area = getCaptureArea();
        if (area == null)
            throw new IllegalStateException("capture area rectangle not set: " + getName());
        Robot robot = robot();
        synchronized (robot) {
            return new SnapShot(id, sequence, getName(), GUIUtil.captureSelectedArea(area, robot));
        }
    }

    /**
     * Lazily creates and caches this area's {@link Robot} via double-checked locking
     * (the field is volatile, making the pattern safe); it stays valid until
     * {@link #setGraphicsDevice(GraphicsDevice)} discards it and captures from the
     * device configured at creation time (the default screen device if none).
     *
     * @return the cached robot
     * @throws AWTException if the platform does not allow screen capture
     */
    private Robot robot() throws AWTException {
        Robot ret = robot;
        if (ret == null) {
            synchronized (this) {
                // re-check under the lock: another thread may have won the race
                ret = robot;
                if (ret == null) {
                    GraphicsDevice device = graphicsDevice;
                    ret = device != null ? new Robot(device) : new Robot();
                    robot = ret;
                }
            }
        }
        return ret;
    }
}
