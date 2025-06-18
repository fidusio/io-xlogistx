package io.xlogistx.http.websocket;

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
        return data.wrap();
    }

    public String toString() {
        return data.asString();
    }

}
