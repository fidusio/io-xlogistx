package io.xlogistx.common.image;

import org.zoxweb.server.io.UByteArrayOutputStream;


import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;

import java.io.IOException;


public final class TextToImage {

    private TextToImage(){}


    public static ImageInfo textToImage(String text, String imageFormat, Font font, Color color, String id) throws IOException {


        BufferedImage image = new BufferedImage(1, 1, BufferedImage.TYPE_INT_ARGB);// Represents an image with 8-bit RGBA color components packed into integer pixels.
        Graphics2D graphics2d = image.createGraphics();
        //Font font = new Font("Arial", Font.ITALIC, 18);
        graphics2d.setFont(font);
        FontMetrics fontmetrics = graphics2d.getFontMetrics();
        int width = fontmetrics.stringWidth(text);
        int height = fontmetrics.getHeight();
        graphics2d.dispose();

        image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        graphics2d = image.createGraphics();
        graphics2d.setRenderingHint(RenderingHints.KEY_ALPHA_INTERPOLATION, RenderingHints.VALUE_ALPHA_INTERPOLATION_QUALITY);
        graphics2d.setRenderingHint(RenderingHints.KEY_COLOR_RENDERING, RenderingHints.VALUE_COLOR_RENDER_QUALITY);
        graphics2d.setFont(font);
        fontmetrics = graphics2d.getFontMetrics();
        graphics2d.setColor(color);
        graphics2d.drawString(text, 0, fontmetrics.getAscent());
        graphics2d.dispose();
        UByteArrayOutputStream ubaos = new UByteArrayOutputStream(256);
        ImageIO.write(image, imageFormat, ubaos);

        return new ImageInfo(System.currentTimeMillis(), id, ubaos.toByteArrayInputStream(), width, height, imageFormat) ;
    }
}
