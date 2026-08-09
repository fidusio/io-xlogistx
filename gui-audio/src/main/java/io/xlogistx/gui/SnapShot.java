package io.xlogistx.gui;

import org.zoxweb.server.io.UByteArrayInputStream;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.shared.util.SUS;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;

/**
 * Immutable snapshot of a captured screen image plus identification metadata:
 * id, source id (typically the {@link SelectionArea} name it was captured from),
 * sequence number and capture timestamp. Holds no reference to the source area,
 * only its id, so snapshots stay valid if the area is mutated or removed.
 * <p>
 * Instances are value objects; use
 * {@link SelectionArea#takeSnapShot(String, long, java.awt.Robot)} to grab the current
 * screen content of a selection area.
 */
public class SnapShot {
    private final BufferedImage image;
    private final String sourceID;
    private final String id;
    private final long sequence;
    private final long timestamp;

    /**
     * Creates a snapshot stamped with the current time.
     *
     * @param id       identifier of the snapshot or its capture session, may be null
     * @param sequence sequence number of the snapshot within its capture stream
     * @param sourceID identifier of the capture source (typically the selection
     *                 area name), may be null
     * @param image    the captured image
     * @throws NullPointerException if image is null
     */
    public SnapShot(String id, long sequence, String sourceID, BufferedImage image) {
        this(id, sequence, System.currentTimeMillis(), sourceID, image);
    }

    /**
     * Creates a snapshot with an explicit timestamp.
     *
     * @param id        identifier of the snapshot or its capture session, may be null
     * @param sequence  sequence number of the snapshot within its capture stream
     * @param timestamp capture time in epoch millis
     * @param sourceID  identifier of the capture source (typically the selection
     *                  area name), may be null
     * @param image     the captured image
     * @throws NullPointerException if image is null
     */
    public SnapShot(String id, long sequence, long timestamp, String sourceID, BufferedImage image) {
        SUS.checkIfNulls("image can't be null", image);
        this.id = id;
        this.sequence = sequence;
        this.timestamp = timestamp;
        this.sourceID = sourceID;
        this.image = image;
    }

    /**
     * @return the captured image
     */
    public BufferedImage getImage() {
        return image;
    }

    /**
     * Encodes the captured image in the given format; {@code "jpg"}/{@code "jpeg"}
     * is encoded via {@link GUIUtil#compressImage(BufferedImage, int, float)} at
     * {@link GUIUtil#DEFAULT_JPG_QUALITY}.
     *
     * @param format image format name, case-insensitive (e.g. "png", "jpg", "gif")
     * @return the encoded image bytes as a stream
     * @throws IOException if the format is unsupported or encoding fails
     */
    public UByteArrayInputStream getImageAsInputStream(String format) throws IOException {
        if ("jpg".equalsIgnoreCase(format) || "jpeg".equalsIgnoreCase(format))
            return GUIUtil.compressImage(getImage(), 0, GUIUtil.DEFAULT_JPG_QUALITY);

        UByteArrayOutputStream out = new UByteArrayOutputStream();
        // ImageIO.write does not throw on an unknown format, it returns false
        if (!ImageIO.write(getImage(), format, out))
            throw new IOException("unsupported image format: " + format);
        return out.toByteArrayInputStream();
    }

    /**
     * @return identifier of the capture source (typically the selection area name),
     *         may be null
     */
    public String getSourceID() {
        return sourceID;
    }

    /**
     * @return identifier of the snapshot or its capture session, may be null
     */
    public String getID() {
        return id;
    }

    /**
     * @return sequence number of the snapshot within its capture stream
     */
    public long getSequence() {
        return sequence;
    }

    /**
     * @return capture time in epoch millis
     */
    public long getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return "SnapShot{" +
                "id='" + id + '\'' +
                ", sequence=" + sequence +
                ", timestamp=" + timestamp +
                ", sourceID=" + sourceID +
                ", image=" + image.getWidth() + "x" + image.getHeight() +
                '}';
    }
}
