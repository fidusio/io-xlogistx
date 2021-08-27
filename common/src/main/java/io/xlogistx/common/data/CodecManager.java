package io.xlogistx.common.data;

import org.zoxweb.shared.filters.ValueFilter;

import org.zoxweb.shared.util.SharedUtil;
import java.util.LinkedHashMap;
import java.util.Map;

public class CodecManager
    extends NamedDescription
{
    private final Map<String, MessageCodec> map = new LinkedHashMap<String, MessageCodec>();
    private final ValueFilter<String, String> nameFilter;
    public CodecManager(String name, ValueFilter nameFilter, String description){
        super(name, description);
        SharedUtil.checkIfNulls("name filter can't b null", nameFilter);
        this.nameFilter = nameFilter;
    }

    public CodecManager add(MessageCodec mc) {
        synchronized (map)
        {
            map.put(mc.getName(), mc);
        }
        return this;
    }

    public MessageCodec lookup(String codecName){
        return map.get(nameFilter.validate(codecName));
    }

    public MessageCodec[] all()
    {
        return map.values().toArray(new MessageCodec[0]);
    }
}
