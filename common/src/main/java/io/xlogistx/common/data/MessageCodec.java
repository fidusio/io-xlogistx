package io.xlogistx.common.data;


import org.zoxweb.shared.util.DataDecoder;
import org.zoxweb.shared.util.DataEncoder;
import org.zoxweb.shared.util.NVGenericMap;

public abstract class MessageCodec<EI, EO, DI, DO>
    extends NamedDescription
    implements DataEncoder<EI, EO>,
        DataDecoder<DI, DO>
{


    protected MessageCodec(String name, String description) {
        super(name, description);
    }

    public String toString()
    {
        return getName() + " : " + getDescription();
    }


}
