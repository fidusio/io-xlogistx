package io.xlogistx.gui;

import org.zoxweb.shared.util.GetName;

import javax.swing.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Base class for status-display panels that map status tags (String or Enum names)
 * to a display value of type M (e.g. a {@link java.awt.Color} for {@link LedWidget},
 * an {@link javax.swing.ImageIcon} for {@link IconStatusWidget}).
 * <p>
 * Subclasses render {@link #currentValue} in their paint method; callers register
 * mappings via {@link #mapStatus(Enum, Object)} / {@link #mapStatus(String, Object)}
 * and switch the display via {@link #setStatus(Enum)} / {@link #setStatus(String)}.
 *
 * @param <M> type of the mapped display value
 */
abstract public class StatusWidget<M>
    extends JPanel
{
    /** The currently displayed mapped value; rendered by the subclass. */
    protected M currentValue;
    /** Registry of status tag to mapped display value. */
    protected final Map<String, M> widgetMap = new HashMap<>();

    /**
     * Looks up the mapped value for an enum status, first by {@link Enum#name()}
     * then, if the enum implements {@link GetName}, by its logical name.
     *
     * @param status enum status tag
     * @return the mapped value, or null if not registered
     */
    public M getStatusMap(Enum<?> status)
    {
        M ret = widgetMap.get(status.name());
        if (ret == null && status instanceof GetName)
            ret = widgetMap.get(((GetName) status).getName());

        return ret;
    }
    /**
     * Looks up the mapped value for a string status tag.
     *
     * @param status status tag
     * @return the mapped value, or null if not registered
     */
    public M getStatusMap(String status)
    {
        return widgetMap.get(status);
    }


    /**
     * Switches the widget to the value mapped to the given status tag and repaints.
     *
     * @param status status tag
     * @return true if the status was registered and applied, false otherwise
     */
    public boolean setStatus(String status)
    {
        return setMappedStatus(getStatusMap(status));
    }

    /**
     * Switches the widget to the value mapped to the given enum status and repaints.
     *
     * @param status enum status tag
     * @return true if the status was registered and applied, false otherwise
     */
    public boolean setStatus(Enum<?> status)
    {
        return setMappedStatus(getStatusMap(status));
    }

    /**
     * Applies a mapped value directly as the current display value and repaints.
     *
     * @param mappedValue value to display; ignored if null
     * @return true if the value was applied, false if it was null
     */
    protected boolean setMappedStatus(M mappedValue)
    {
        if(mappedValue != null)
        {
            currentValue = mappedValue;
            repaint();
            return true;
        }
        return false;
    }

    /**
     * Registers a mapping from an enum tag to a display value. The mapping is stored
     * under {@link Enum#name()} and additionally, if the enum implements
     * {@link GetName}, under its logical name.
     *
     * @param tag    enum status tag
     * @param mapped display value associated with the status
     * @param <V>    concrete widget type
     * @return this widget for chaining
     */
    public <V extends StatusWidget<M>> V mapStatus(Enum<?> tag, M mapped) {
        widgetMap.put(tag.name(), mapped);
        if (tag instanceof GetName) {
            widgetMap.put(((GetName) tag).getName(), mapped);
        }
        return (V)this;
    }

    /**
     * Registers a mapping from a string tag to a display value.
     *
     * @param tag    status tag
     * @param mapped display value associated with the status
     * @param <V>    concrete widget type
     * @return this widget for chaining
     */
    public <V extends StatusWidget<M>> V mapStatus(String tag, M mapped) {
        widgetMap.put(tag, mapped);
        return (V)this;
    }
}
