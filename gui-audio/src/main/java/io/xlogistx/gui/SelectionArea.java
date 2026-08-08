package io.xlogistx.gui;

import org.zoxweb.shared.util.NamedDescription;
import org.zoxweb.shared.util.SetDescription;
import org.zoxweb.shared.util.SetName;

import java.awt.*;

/**
 * A named rectangular region of the screen, the unit of capture used by
 * {@link SelectionAreaSet} and {@link SnapShot}.
 * <p>
 * The rectangle is typically produced by {@link GUIUtil#captureSelectedArea()}
 * (drag selection) and may be null until set, or empty when the user clicked
 * without dragging — consumers must handle both. The field is volatile so the
 * rectangle can be swapped while capture sweeps read it from another thread.
 */
public class SelectionArea
    implements SetName, SetDescription {

    private NamedDescription namedDescription;
    private volatile Rectangle captureArea;


    /**
     * Creates an unnamed area with no rectangle; populate via the setters.
     */
    public SelectionArea() {
        namedDescription = new NamedDescription();
    }

    /**
     * Creates a fully populated area.
     *
     * @param name        name of the area, used as the {@link SnapShot} id
     * @param description optional description, may be null
     * @param captureArea screen rectangle to capture, may be null until selected
     */
    public SelectionArea(String name, String description, Rectangle captureArea) {
        this();
        setName(name);
        setDescription(description);
        this.captureArea = captureArea;
    }

    /**
     * @return the screen rectangle to capture; null if not selected yet, may be
     *         empty (click without drag)
     */
    public Rectangle getSelectionArea() {
        return captureArea;
    }

    /**
     * Sets the screen rectangle to capture.
     *
     * @param selectedArea the new rectangle, in screen coordinates
     * @return this instance, for fluent chaining
     */
    public SelectionArea setSelectionArea(Rectangle selectedArea) {
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
}
