package io.xlogistx.common.data;

import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.SetDescription;
import org.zoxweb.shared.util.SharedUtil;

public class NamedDescription
        implements GetName, SetDescription {
    private final String name;
    private String description;


    public NamedDescription(String name){
        this(name, null);
    }
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
    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String getName() {
        return name;
    }

}
