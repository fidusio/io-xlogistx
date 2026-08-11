package io.xlogistx.gui;

import org.zoxweb.server.io.UByteArrayInputStream;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.shared.util.DataEncoder;
import org.zoxweb.shared.util.SUS;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * Immutable snapshot of a captured screen image plus identification metadata:
 * id, source id (typically the {@link CaptureArea} name it was captured from),
 * sequence number and capture timestamp. Holds no reference to the source area,
 * only its id, so snapshots stay valid if the area is mutated or removed.
 * <p>
 * Instances are value objects; use
 * {@link CaptureArea#takeSnapShot(String, long)} to grab the current
 * screen content of a capture area.
 */
public class SnapShot
    implements Comparable<SnapShot>, DataEncoder<String, UByteArrayInputStream> {
    private final BufferedImage image;
    private final String sourceID;
    private final String id;
    private final long sequence;
    private final long timestamp;
    // lazily computed content hash, 0 = not computed yet (benign race: the
    // computation is deterministic, so concurrent writers store the same value)
    private int imageHash;

    /**
     * Creates a snapshot stamped with the current time.
     *
     * @param id       identifier of the snapshot or its capture session, may be null
     * @param sequence sequence number of the snapshot within its capture stream
     * @param sourceID identifier of the capture source (typically the capture
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
     * @param sourceID  identifier of the capture source (typically the capture
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
     * {@link DataEncoder} form of {@link #exportAsInputStream(String)}: encodes the
     * captured image in the given format, wrapping any {@link IOException} in an
     * unchecked one since the {@link DataEncoder} contract cannot throw checked
     * exceptions.
     *
     * @param format image format name, case-insensitive (e.g. "png", "jpg")
     * @return the encoded image bytes
     * @throws UncheckedIOException if the format is unsupported or encoding fails
     */
    @Override
    public UByteArrayInputStream encode(String format) {
        try {
            return exportAsInputStream(format);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
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
    public UByteArrayInputStream exportAsInputStream(String format) throws IOException {
        if ("jpg".equalsIgnoreCase(format) || "jpeg".equalsIgnoreCase(format))
            return GUIUtil.compressImage(getImage(), GUIUtil.AI_IMAGE_MAX_DIMENSION, GUIUtil.DEFAULT_JPG_QUALITY);

        UByteArrayOutputStream out = new UByteArrayOutputStream();
        // ImageIO.write does not throw on an unknown format, it returns false
        if (!ImageIO.write(getImage(), format, out))
            throw new IOException("unsupported image format: " + format);
        return out.toByteArrayInputStream();
    }

    /**
     * @return identifier of the capture source (typically the capture area name),
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

    /**
     * Compares this snapshot's image with another snapshot's, pixel by pixel, via
     * {@link GUIUtil#compareImages(BufferedImage, BufferedImage)}; metadata (id,
     * source id, sequence, timestamp) is ignored. Useful to detect whether the
     * screen content of an area changed between two captures.
     *
     * @param other the snapshot to compare against, may be null
     * @return true if other is non-null and both images have identical dimensions
     *         and every pixel matches; false otherwise
     */
    public boolean compare(SnapShot other) {
        return other != null && GUIUtil.compareImages(image, other.getImage());
    }

    /**
     * Orders snapshots by image content only — width, then height, then pixel
     * values via {@link GUIUtil#compareImagesOrder(BufferedImage, BufferedImage)};
     * metadata (id, source id, sequence, timestamp) is ignored. Returns 0 exactly
     * when {@link #compare(SnapShot)} returns true, so the natural ordering is
     * consistent with {@link #equals(Object)}.
     *
     * @param other the snapshot to compare against
     * @return negative, zero or positive per the {@link Comparable} contract
     * @throws NullPointerException if other is null
     */
    @Override
    public int compareTo(SnapShot other) {
        return GUIUtil.compareImagesOrder(image, other.getImage());
    }

    /**
     * Equality on image content only — same dimensions and every pixel equal, via
     * {@link GUIUtil#compareImages(BufferedImage, BufferedImage)}; metadata (id,
     * source id, sequence, timestamp) is ignored. Accepts both a {@link SnapShot}
     * and a raw {@link BufferedImage}. Two snapshots of unchanged screen content
     * are therefore equal, so hash-based collections deduplicate them.
     * <p>
     * Note the BufferedImage form is one-way: {@code snapShot.equals(image)}
     * compares content, but {@code image.equals(snapShot)} is identity-based and
     * always false, and BufferedImage's identity hash means hash-based collection
     * lookups only match between SnapShots.
     *
     * @param o the object to compare against, may be null
     * @return true if o is a SnapShot or BufferedImage with pixel-identical
     *         image content
     */
    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o instanceof SnapShot)
            return GUIUtil.compareImages(image, ((SnapShot) o).getImage());
        if (o instanceof BufferedImage)
            return GUIUtil.compareImages(image, (BufferedImage) o);
        return false;
    }

    /**
     * Content hash matching {@link #equals(Object)}: derived from the image's
     * dimensions and pixels via {@link GUIUtil#imageHashCode(BufferedImage)},
     * computed once on first use and cached (the image is immutable by contract).
     *
     * @return the image content hash
     */
    @Override
    public int hashCode() {
        int h = imageHash;
        if (h == 0) {
            h = GUIUtil.imageHashCode(image);
            if (h == 0)
                h = 1; // reserve 0 as the not-computed sentinel
            imageHash = h;
        }
        return h;
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
