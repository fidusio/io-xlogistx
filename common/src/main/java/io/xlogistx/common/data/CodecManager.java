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


    public CodecManager add(MessageCodec mc)
    {
        return add(mc.getName(), mc);
    }

    public CodecManager add(String codecName, MessageCodec mc) {
        codecName = nameFilter.validate(codecName);
        synchronized (map)
        {
            map.put(codecName, mc);
        }
        return this;
    }

    public MessageCodec lookup(String codecName){
        return map.get(nameFilter.validate(codecName));
    }
}
