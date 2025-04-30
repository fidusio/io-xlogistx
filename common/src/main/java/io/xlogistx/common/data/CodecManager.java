package io.xlogistx.common.data;

import org.zoxweb.shared.filters.ValueFilter;
import org.zoxweb.shared.util.NamedDescription;
import org.zoxweb.shared.util.SUS;

import java.util.LinkedHashMap;
import java.util.Map;

public class CodecManager<V extends MessageCodec>
    extends NamedDescription
{
    private final Map<String, V> map = new LinkedHashMap<String, V>();
    private final ValueFilter<String, String> nameFilter;
    public CodecManager(String name, ValueFilter<String, String> nameFilter, String description){
        super(name, description);
        SUS.checkIfNulls("name filter can't b null", nameFilter);
        this.nameFilter = nameFilter;
    }

    public CodecManager add(V mc) {
        synchronized (map)
        {
            map.put(nameFilter.validate(mc.getName()), mc);
        }
        return this;
    }

    public V lookup(String codecName){
        return map.get(nameFilter.validate(codecName));
    }

    public V[] all()
    {
        return (V[])map.values().toArray(new MessageCodec[0]);
    }
}
