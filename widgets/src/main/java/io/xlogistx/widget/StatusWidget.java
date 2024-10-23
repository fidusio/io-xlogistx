package io.xlogistx.widget;

import org.zoxweb.shared.util.GetName;

import javax.swing.*;
import java.util.HashMap;
import java.util.Map;

abstract public class StatusWidget<M>
    extends JPanel
{
    protected M currentValue;
    protected final Map<String, M> windgetMap = new HashMap<>();

    public M getStatusMap(Enum<?> status)
    {
        M ret = windgetMap.get(status.name());
        if (ret == null && status instanceof GetName)
            ret = windgetMap.get(((GetName) status).getName());

        return ret;
    }
    public M getStatusMap(String status)
    {
        return windgetMap.get(status);
    }


    public boolean setStatus(String status)
    {
        return setMappedStatus(getStatusMap(status));
    }

    public boolean setStatus(Enum<?> status)
    {
        return setMappedStatus(getStatusMap(status));
    }

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

    public StatusWidget<M> mapStatus(Enum<?> tag, M mapped) {
        windgetMap.put(tag.name(), mapped);
        if (tag instanceof GetName) {
            windgetMap.put(((GetName) tag).getName(), mapped);
        }
        return this;
    }

    /**
     * Maps a String tag to an Icon.
     *
     * @param tag   The String representing the status.
     * @param mapped  The Icon associated with the status.
     * @return The IconWidget instance for chaining.
     */
    public StatusWidget<M> mapStatus(String tag, M mapped) {
        windgetMap.put(tag, mapped);
        return this;
    }
}
