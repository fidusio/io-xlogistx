package io.xlogistx.http.websocket;

import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.shared.util.BytesArray;

import javax.websocket.PongMessage;
import java.nio.ByteBuffer;

public class WSPongMessage
        implements PongMessage {

    public final BytesArray data;

    WSPongMessage(BytesArray data) {
        this.data = data;
    }

    @Override
    public ByteBuffer getApplicationData() {
        return ByteBufferUtil.toByteBuffer(data);
    }

    public String toString() {
        return data.asString();
    }

}
