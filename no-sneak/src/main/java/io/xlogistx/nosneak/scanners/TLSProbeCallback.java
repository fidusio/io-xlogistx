package io.xlogistx.nosneak.scanners;

import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsFatalAlert;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

/**
 * Base class for NIO TLS probe callbacks.
 * Handles the non-blocking TLS handshake lifecycle using Bouncy Castle's
 * TlsClientProtocol in non-blocking mode.
 * <p>
 * Subclasses implement:
 * <ul>
 *   <li>{@link #createTlsClient()} - provide the configured TLS client</li>
 *   <li>{@link #onProbeSuccess()} - called when handshake succeeds</li>
 *   <li>{@link #onProbeFailure(Throwable)} - called when handshake fails</li>
 * </ul>
 */
public abstract class TLSProbeCallback extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(TLSProbeCallback.class).setEnabled(false);

    protected TlsClientProtocol protocol;
    private final ByteBuffer readBuffer = ByteBufferUtil.allocateByteBuffer(16384);
    private volatile boolean completed = false;

    private volatile SelectionKey selectionKey;

    protected TLSProbeCallback(IPAddress address) {
        super(address);
        closeableDelegate.setDelegate(()->{
            if (selectionKey != null) {
                selectionKey.cancel();
            }
            IOUtil.close(getChannel());
            ByteBufferUtil.cache(readBuffer);
        });
    }

    /**
     * Create the TLS client to use for this probe.
     */
    protected abstract DefaultTlsClient createTlsClient();

    /**
     * Called when the TLS handshake completes successfully.
     */
    protected abstract void onProbeSuccess();

    /**
     * Called when the TLS handshake fails.
     *
     * @param cause the failure cause (may be TlsFatalAlert for expected rejections)
     */
    protected abstract void onProbeFailure(Throwable cause);

    @Override
    protected void connectedFinished() throws IOException {
        if (completed) return;

        try {
            // Initialize BC TLS protocol in non-blocking mode (no-arg constructor)
            protocol = new TlsClientProtocol();
            DefaultTlsClient client = createTlsClient();

            // Begin handshake - this generates ClientHello
            protocol.connect(client);

            // Flush ClientHello to network
            flushOutput();
        } catch (TlsFatalAlert e) {
            complete();
            onProbeFailure(e);
        } catch (Exception e) {
            complete();
            onProbeFailure(e);
        }
    }

    @Override
    public void accept(SelectionKey key) {
        if (completed) return;

        if(this.selectionKey != null && this.selectionKey != key) {
            log.getLogger().info("Key Mismatch current " + this.selectionKey + " new key " + key);

        }

        this.selectionKey = key;

        try {
            if (key.isReadable() && protocol != null) {
                SocketChannel channel = (SocketChannel) key.channel();
                readBuffer.clear();
                int bytesRead = channel.read(readBuffer);

                if (bytesRead == -1) {
                    key.cancel();
                    complete();
                    onProbeFailure(new IOException("Connection closed by peer"));
                    return;
                }

                if (bytesRead > 0) {
                    readBuffer.flip();
                    byte[] bytes = new byte[readBuffer.remaining()];
                    readBuffer.get(bytes);

                    protocol.offerInput(bytes, 0, bytes.length);

                    // Flush any response data (e.g., Finished message)
                    flushOutput();

                    // Check if handshake is done
                    if (!protocol.isHandshaking()) {
                        complete();
                        onProbeSuccess();
                    }
                }
            }
        } catch (TlsFatalAlert e) {
            // Expected for probe rejections (e.g., handshake_failure, protocol_version)
            key.cancel();
            complete();
            onProbeFailure(e);
        } catch (Exception e) {
            key.cancel();
            complete();
            onProbeFailure(e);
        }
    }

    @Override
    public void accept(ByteBuffer buffer) {
        // Delegate to SelectionKey-based accept
    }

    @Override
    public void exception(Throwable e) {
        if (completed) return;
        complete();
        onProbeFailure(e);
    }

    /**
     * Flush BC TLS output to the network channel.
     */
    protected void flushOutput() throws IOException {
        int available = protocol.getAvailableOutputBytes();
        if (available > 0) {
            byte[] outputData = new byte[available];
            int read = protocol.readOutput(outputData, 0, available);
            if (read > 0) {
                ByteBuffer writeBuffer = ByteBuffer.wrap(outputData, 0, read);
                ByteBufferUtil.write(getChannel(), writeBuffer, false);
            }
        }
    }

    private void complete() {
        completed = true;
        try {
            if (protocol != null) {
                protocol.close();
            }
        } catch (Exception ignored) {
        }
        try {
            close();
        } catch (Exception ignored) {
        }
    }

}
