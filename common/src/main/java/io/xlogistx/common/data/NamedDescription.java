package io.xlogistx.common.data;

import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.SharedUtil;

public class NamedDescription
        implements GetName, GetDescription {
    private final String name;
    private final String description;

    public NamedDescription(String name, String description){
    SharedUtil.checkIfNulls("name can't be null.", name);
        this.name = name;
        this.description = description;
    }


    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public String getName() {
        return name;
    }
}
