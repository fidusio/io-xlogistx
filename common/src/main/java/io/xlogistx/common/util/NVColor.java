package io.xlogistx.common.util;

import org.zoxweb.server.util.ServerUtil;
import org.zoxweb.shared.util.DataEncoder;
import org.zoxweb.shared.util.GetNameValue;
import org.zoxweb.shared.util.SUS;

import java.awt.*;
import java.util.HashMap;
import java.util.Map;

public enum NVColor implements GetNameValue<Color> {
    RED("red", Color.RED),
    GREEN("green", Color.GREEN),
    BLUE("blue", Color.BLUE),
    WHITE("white", Color.WHITE),
    GREY("grey", Color.GRAY),
    MAGENTA("magenta", Color.MAGENTA),
    PINK("pink", Color.PINK),
    ORANGE("orange", Color.ORANGE),
    BLACK("black", Color.BLACK),
    START_COLOR("start-color", new Color(255, 0, 0)),
    MID_COLOR("mid-color", new Color(0, 128, 255)),
    END_COLOR("end-color", new Color(0, 255, 0)),
    LIGHT_RED("light-red", new Color(255, 102, 102)),
    BOOTSTRAP_RED("bootstrap-red", new Color(0Xdc3545)),
    DARK_RED("dark-read", new Color(139, 0, 0)),
    LIGHT_GREEN("light-green", new Color(144, 238, 144)),
    BOOTSTRAP_GREEN("bootstrap-green", new Color(0X28a745)),
    DARK_GREEN("dark-green", new Color(0, 100, 0)),
    MATERIAL_BLUE("mistral-blue", new Color(33, 150, 243)),
    BOOTSTRAP_BLUE("bootstrap-blue", new Color(0X2196F3)),
    IOS_BLUE("iso-blue", new Color(10, 132, 255)),
    ;

    private static Map<String, Color> colorMap;

    private final String name;

    NVColor(String name, Color color) {
        this.name = DataEncoder.StringLower.encode(name);
        add(name, color);
    }

    private static Map<String, Color> map() {
        if (colorMap == null) {
            ServerUtil.LOCK.lock();
            try {
                if (colorMap == null)
                    colorMap = new HashMap<>();
            } finally {
                ServerUtil.LOCK.unlock();
            }
        }
        return colorMap;
    }
    public static void add(String name, Color color) {

        SUS.checkIfNulls("name or color null", name, color);
        map().put(DataEncoder.StringLower.encode(name), color);
    }

    public static void remove(String name) {
        map().remove(DataEncoder.StringLower.encode(name));
    }

    public static Color color(String name) {
        return map().get(DataEncoder.StringLower.encode(name));
    }

    /**
     * @return the name of the object
     */
    @Override
    public String getName() {
        return name;
    }

    /**
     * Returns the value.
     *
     * @return typed value
     */
    @Override
    public Color getValue() {
        return color(name);
    }


    public Color color() {
        return color(name);
    }
}
