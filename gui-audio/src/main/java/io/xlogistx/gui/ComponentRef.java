package io.xlogistx.gui;

import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetDisplayName;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.NVEntity;
import org.zoxweb.shared.util.SUS;

import java.awt.Component;

/**
 * Binds a Swing component to what it stands for: the <b>source</b> object it was built from (an
 * enum constant, an {@link NVEntity}, anything) and that object's name, description and display
 * name through zoxweb's {@link GetName}, {@link GetDescription} and {@link GetDisplayName}.
 * <p>
 * A control that builds one component per option keeps a ref per component, so it can label the
 * component with {@link #getDisplayName()}, explain it with {@link #getDescription()} (the
 * tooltip), and hand {@link #getSource()} back when the component is picked — no index-to-constant
 * mapping on either side:
 * <pre>
 * ComponentRef&lt;Timing&gt; ref = new ComponentRef&lt;Timing&gt;(button, Timing.T3);
 * ref.getDisplayName();   // "T3"           (Timing implements GetDisplayName)
 * ref.getDescription();   // null, or the constant's text when Timing implements GetDescription
 * ref.getSource();        // Timing.T3
 * </pre>
 * <b>Resolution.</b> When the source implements one of the three interfaces, that value is read
 * live on every call (an entity renamed after the ref was made shows its new name); a null from
 * the source, or a source without the interface, falls back to the strings given or derived at
 * construction. The name of an enum constant defaults to {@link Enum#name()}; the display name
 * defaults to the name, so a label built from any enum is never blank.
 *
 * @param <S> the source type: the enum, the entity, or {@link Object} for a ref built from strings
 */
public class ComponentRef<S> implements GetName, GetDescription, GetDisplayName {

    private final Component component;
    private final S source;
    private final String name;
    private final String description;
    private final String displayName;

    /**
     * A ref over a source object; its name, description and display name come from the source's
     * interfaces (live) and, for an enum constant, default to its {@link Enum#name()}.
     */
    public ComponentRef(Component component, S source) {
        SUS.checkIfNulls("component or source null", component, source);
        this.component = component;
        this.source = source;
        this.name = source instanceof Enum ? ((Enum<?>) source).name()
                : source instanceof String ? (String) source : null; // a plain string names itself
        this.description = null;
        this.displayName = null;
    }

    /**
     * A ref over a source whose display name is overridden: the same option worded differently
     * in one place (a menu that says "Assistant chat" for the Chat page). Null keeps the source's.
     */
    public ComponentRef(Component component, S source, String displayName) {
        SUS.checkIfNulls("component or source null", component, source);
        this.component = component;
        this.source = source;
        this.name = source instanceof Enum ? ((Enum<?>) source).name()
                : source instanceof String ? (String) source : null;
        this.description = null;
        this.displayName = displayName;
    }

    /**
     * A ref over a source worded by the caller: a list row whose text and sub-line come from the
     * host's label functions rather than the item's own interfaces. Nulls keep the source's.
     */
    public ComponentRef(Component component, S source, String displayName, String description) {
        SUS.checkIfNulls("component or source null", component, source);
        this.component = component;
        this.source = source;
        this.name = source instanceof Enum ? ((Enum<?>) source).name()
                : source instanceof String ? (String) source : null;
        this.description = description;
        this.displayName = displayName;
    }

    /** A ref with no source: the three strings are all it knows. */
    public ComponentRef(Component component, String name, String description, String displayName) {
        SUS.checkIfNull("component null", component);
        this.component = component;
        this.source = null;
        this.name = name;
        this.description = description;
        this.displayName = displayName;
    }

    /** The component, cast to what the caller expects. */
    @SuppressWarnings("unchecked")
    public <T extends Component> T getComponent() {
        return (T) component;
    }

    /** The object this ref was built from; null for a ref built from strings. */
    public S getSource() {
        return source;
    }

    /** The source's name when it has one, else the name given or derived at construction. */
    @Override
    public String getName() {
        if (source instanceof GetName) {
            String n = ((GetName) source).getName();
            if (n != null) return n;
        }
        return name;
    }

    /** The description given (an override), else the source's; may be null. */
    @Override
    public String getDescription() {
        if (description != null) return description;
        if (source instanceof GetDescription) return ((GetDescription) source).getDescription();
        return null;
    }

    /** The display name given (an override), else the source's, else {@link #getName()}. */
    @Override
    public String getDisplayName() {
        if (displayName != null) return displayName;
        if (source instanceof GetDisplayName) {
            String d = ((GetDisplayName) source).getDisplayName();
            if (d != null) return d;
        }
        return getName();
    }

    @Override
    public String toString() {
        return "ComponentRef[" + getName() + (source != null ? " <- " + source : "") + "]";
    }
}
