package io.xlogistx.common.http;

import org.zoxweb.shared.protocol.ProtoSession;
import org.zoxweb.shared.util.CollectionAsArray;

import java.util.LinkedHashSet;

public class ProtoSessionSet {
    public final CollectionAsArray<ProtoSession<?,?>> sessions = new CollectionAsArray<ProtoSession<?,?>>(new LinkedHashSet<>(), new ProtoSession[0]);

    public ProtoSessionSet() {
    }

    public boolean canClose() {
        for (ProtoSession<?,?> session : sessions.asArray()){
            if  (!session.canClose())
                return false;
        }

        return true;
    }

}
