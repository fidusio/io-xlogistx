package io.xlogistx.gui;

import org.zoxweb.shared.util.SUS;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.geom.CubicCurve2D;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Path2D;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure Java renderer for the Mermaid <b>flowchart</b> subset: no browser, no
 * JavaScript, no network. Used by {@link MDToPDF} to turn {@code ```mermaid}
 * fenced blocks into images.
 *
 * <h2>Supported syntax</h2>
 * <ul>
 *   <li>Header {@code flowchart} or {@code graph} with direction {@code TD},
 *       {@code TB}, {@code BT}, {@code LR} or {@code RL}.</li>
 *   <li>Nodes {@code id[text]}, {@code id(text)}, {@code id([text])},
 *       {@code id[[text]]}, {@code id[(text)]}, {@code id((text))},
 *       {@code id{text}}, {@code id{{text}}}, {@code id[/text/]},
 *       {@code id[\text\]}, {@code id>text]}; a bare {@code id} shows the id.
 *       Labels may be quoted, contain {@code <br/>} line breaks and the basic
 *       HTML entities; other tags are stripped.</li>
 *   <li>Edges {@code -->}, {@code ---}, {@code -.->}, {@code -.-}, {@code ==>},
 *       {@code ===}, with a label as {@code -->|text|} or {@code -- text -->},
 *       chained ({@code A --> B --> C}) and fanned with {@code &}
 *       ({@code A & B --> C}).</li>
 *   <li>Statements separated by newlines or semicolons; {@code %%} comments.</li>
 * </ul>
 * {@code subgraph}/{@code end}, {@code classDef}, {@code class}, {@code style},
 * {@code linkStyle}, {@code click} and {@code direction} lines are accepted and
 * ignored (nodes inside a subgraph are still drawn, ungrouped). Anything else
 * throws {@link IllegalArgumentException}, so callers can fall back to showing
 * the source.
 *
 * <h2>Layout</h2>
 * Layered: back edges are found by depth-first search, layers by longest path,
 * the order within a layer by a few barycenter sweeps, and positions by
 * centering each node under (or over) its neighbours. Forward edges are smooth
 * cubic curves between layers, same-layer edges straight lines, back edges loop
 * around the side. Colors are a neutral grey theme (light grey boxes, grey edges,
 * dark text) rather than Mermaid's lavender default.
 */
public final class MermaidRenderer {

    /** Node shapes, in Mermaid's terms. */
    public enum Shape {
        RECT, ROUND, STADIUM, SUBROUTINE, CYLINDER, CIRCLE, DIAMOND, HEXAGON, PARALLELOGRAM, ASYMMETRIC
    }

    /** A parsed node; geometry is filled in by the layout. */
    public static final class Node {
        private final String id;
        private String label;
        private Shape shape = Shape.RECT;
        private final List<Edge> out = new ArrayList<>();
        private final List<Edge> in = new ArrayList<>();
        private int layer = -1;
        private int order;
        private float mainSize, crossSize, main, cross;
        private float x, y, w, h;

        Node(String id) {
            this.id = id;
            this.label = id;
        }

        /** @return the node id */
        public String getId() {
            return id;
        }

        /** @return the label, lines separated by {@code \n} */
        public String getLabel() {
            return label;
        }

        /** @return the shape */
        public Shape getShape() {
            return shape;
        }

        /** @return the layer index assigned by the layout (0 = first) */
        public int getLayer() {
            return layer;
        }

        /** @return the bounds in pixels at scale 1, valid after rendering */
        public Rectangle2D.Float getBounds() {
            return new Rectangle2D.Float(x, y, w, h);
        }

        @Override
        public String toString() {
            return id + shapeOpen(shape) + label.replace('\n', '|') + shapeClose(shape);
        }
    }

    /** A parsed edge. */
    public static final class Edge {
        private final Node from, to;
        private final String label;
        private final boolean arrow, dotted, thick;
        private boolean back;

        Edge(Node from, Node to, String label, boolean arrow, boolean dotted, boolean thick) {
            this.from = from;
            this.to = to;
            this.label = label;
            this.arrow = arrow;
            this.dotted = dotted;
            this.thick = thick;
        }

        public Node getFrom() {
            return from;
        }

        public Node getTo() {
            return to;
        }

        /** @return the label or null */
        public String getLabel() {
            return label;
        }

        public boolean hasArrow() {
            return arrow;
        }

        public boolean isDotted() {
            return dotted;
        }

        public boolean isThick() {
            return thick;
        }

        @Override
        public String toString() {
            return from.id + (dotted ? " -.-" : thick ? " ==" : " --") + (label != null ? "|" + label + "|" : "")
                    + (arrow ? "> " : "- ") + to.id;
        }
    }

    /** The parsed flowchart. */
    public static final class Graph {
        private final boolean vertical, reversed;
        private final LinkedHashMap<String, Node> nodes = new LinkedHashMap<>();
        private final List<Edge> edges = new ArrayList<>();
        private float width, height;

        Graph(boolean vertical, boolean reversed) {
            this.vertical = vertical;
            this.reversed = reversed;
        }

        /** @return true for TD/TB/BT, false for LR/RL */
        public boolean isVertical() {
            return vertical;
        }

        /** @return true for BT/RL */
        public boolean isReversed() {
            return reversed;
        }

        /** @return nodes in definition order */
        public Collection<Node> getNodes() {
            return Collections.unmodifiableCollection(nodes.values());
        }

        /** @return the node with that id, or null */
        public Node getNode(String id) {
            return nodes.get(id);
        }

        /** @return edges in definition order */
        public List<Edge> getEdges() {
            return Collections.unmodifiableList(edges);
        }

        /** @return image width in pixels at scale 1, valid after rendering */
        public float getWidth() {
            return width;
        }

        /** @return image height in pixels at scale 1, valid after rendering */
        public float getHeight() {
            return height;
        }

        Node node(String id) {
            Node n = nodes.get(id);
            if (n == null) {
                n = new Node(id);
                nodes.put(id, n);
            }
            return n;
        }

        void addEdge(Node from, Node to, EdgeSpec spec) {
            Edge e = new Edge(from, to, spec.label, spec.arrow, spec.dotted, spec.thick);
            edges.add(e);
            from.out.add(e);
            to.in.add(e);
        }
    }

    // ------------------------------------------------------------------ theme

    private static final Font FONT = new Font(Font.SANS_SERIF, Font.PLAIN, 14);
    private static final Font EDGE_FONT = new Font(Font.SANS_SERIF, Font.PLAIN, 12);
    // neutral grey theme (as the Claude app renders Mermaid), not Mermaid's lavender default
    private static final Color NODE_FILL = new Color(0xED, 0xED, 0xEA);
    private static final Color NODE_STROKE = new Color(0xD2, 0xD2, 0xCD);
    private static final Color TEXT = new Color(0x33, 0x33, 0x33);
    private static final Color EDGE = new Color(0x9A, 0x9A, 0x9A);
    private static final Color EDGE_LABEL_BG = new Color(0xF2, 0xF2, 0xEE);
    private static final float PAD_X = 16, PAD_Y = 12, LAYER_GAP = 52, NODE_GAP = 32, MARGIN = 16;
    /** Labels wider than this are word-wrapped, like Mermaid's default wrapping width. */
    private static final float MAX_LABEL_WIDTH = 220;
    private static final float ARROW = 8;
    /** Extra cross-axis room reserved when back edges loop around the diagram's far side. */
    private static final float BACK_EDGE_ROOM = 48;

    private static final Pattern HEADER = Pattern.compile("(?i)^(flowchart|graph)\\s*(TD|TB|BT|LR|RL)?\\s*$");
    private static final Pattern TEXT_ARROW = Pattern.compile("\\s*(.*?)\\s*(-{2,}>|-{3,}|\\.-+>|\\.-+|={2,}>|={3,})");
    private static final Pattern BR = Pattern.compile("(?i)<br\\s*/?>");
    private static final Pattern TAG = Pattern.compile("<[^>]+>");
    private static final Pattern ENTITY = Pattern.compile("&(#\\d+|#x[0-9a-fA-F]+|amp|lt|gt|quot|apos|nbsp);");

    /** Openers (longest first), their closers and the resulting shape. */
    private static final Object[][] OPENERS = {
            {"((", "))", Shape.CIRCLE},
            {"([", "])", Shape.STADIUM},
            {"[[", "]]", Shape.SUBROUTINE},
            {"[(", ")]", Shape.CYLINDER},
            {"[/", "/]", Shape.PARALLELOGRAM},
            {"[\\", "\\]", Shape.PARALLELOGRAM},
            {"{{", "}}", Shape.HEXAGON},
            {"{", "}", Shape.DIAMOND},
            {"[", "]", Shape.RECT},
            {"(", ")", Shape.ROUND},
            {">", "]", Shape.ASYMMETRIC},
    };

    private MermaidRenderer() {
    }

    // ------------------------------------------------------------------- api

    /**
     * @param source Mermaid source
     * @return true if the first statement is a {@code flowchart}/{@code graph} header
     */
    public static boolean isFlowchart(String source) {
        if (source == null)
            return false;
        for (String st : statements(source)) {
            String s = st.trim();
            if (!s.isEmpty())
                return HEADER.matcher(s).matches();
        }
        return false;
    }

    /**
     * Parses a flowchart.
     *
     * @param source the Mermaid source, never null
     * @return the graph (not laid out)
     * @throws IllegalArgumentException if the source is not a flowchart this renderer understands
     */
    public static Graph parse(String source) {
        SUS.checkIfNull("source null", source);
        Graph g = null;
        for (String st : statements(source)) {
            String s = st.trim();
            if (s.isEmpty())
                continue;
            if (g == null) {
                Matcher m = HEADER.matcher(s);
                if (!m.matches())
                    throw new IllegalArgumentException("not a flowchart header: " + s);
                String dir = m.group(2) == null ? "TD" : m.group(2).toUpperCase(Locale.ROOT);
                g = new Graph(!dir.equals("LR") && !dir.equals("RL"), dir.equals("BT") || dir.equals("RL"));
                continue;
            }
            String lower = s.toLowerCase(Locale.ROOT);
            if (startsWithWord(lower, "subgraph") || lower.equals("end") || startsWithWord(lower, "classdef")
                    || startsWithWord(lower, "class") || startsWithWord(lower, "style")
                    || startsWithWord(lower, "linkstyle") || startsWithWord(lower, "click")
                    || startsWithWord(lower, "direction"))
                continue;
            new Cursor(s).statement(g);
        }
        if (g == null)
            throw new IllegalArgumentException("empty diagram");
        if (g.nodes.isEmpty())
            throw new IllegalArgumentException("diagram has no nodes");
        return g;
    }

    /**
     * Parses, lays out and paints a flowchart.
     *
     * @param source the Mermaid source, never null
     * @param scale  device scale; 2 gives a crisp image for print at half the pixel size
     * @return an ARGB image with a white background
     * @throws IllegalArgumentException if the source cannot be parsed
     */
    public static BufferedImage render(String source, float scale) {
        Graph g = parse(source);
        return render(g, scale);
    }

    /**
     * Lays out and paints an already parsed graph.
     *
     * @param g     the graph, never null
     * @param scale device scale, must be positive
     * @return an ARGB image with a white background
     */
    public static BufferedImage render(Graph g, float scale) {
        SUS.checkIfNull("graph null", g);
        if (scale <= 0)
            throw new IllegalArgumentException("scale must be positive");
        layout(g);
        int w = Math.max(1, Math.round(g.width * scale)), h = Math.max(1, Math.round(g.height * scale));
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = img.createGraphics();
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
            g2.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
            g2.setColor(Color.WHITE);
            g2.fillRect(0, 0, w, h);
            g2.scale(scale, scale);
            for (Edge e : g.edges)
                paintEdge(g2, g, e);
            for (Node n : g.nodes.values())
                paintNode(g2, n);
        } finally {
            g2.dispose();
        }
        return img;
    }

    /**
     * {@link #render(String, float)} encoded as PNG.
     *
     * @param source the Mermaid source
     * @param scale  device scale
     * @return PNG bytes
     * @throws IOException if encoding fails
     */
    public static byte[] renderPNG(String source, float scale) throws IOException {
        BufferedImage img = render(source, scale);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, "png", out);
        return out.toByteArray();
    }

    // --------------------------------------------------------------- parsing

    /** Splits on newlines and top-level semicolons, dropping {@code %%} comments. */
    private static List<String> statements(String source) {
        List<String> ret = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        int depth = 0;
        boolean quoted = false;
        int n = source.length();
        for (int i = 0; i < n; i++) {
            char c = source.charAt(i);
            if (c == '"')
                quoted = !quoted;
            if (!quoted) {
                if (c == '%' && i + 1 < n && source.charAt(i + 1) == '%') {
                    while (i < n && source.charAt(i) != '\n')
                        i++;
                    ret.add(cur.toString());
                    cur.setLength(0);
                    continue;
                }
                if (c == '[' || c == '(' || c == '{')
                    depth++;
                else if (c == ']' || c == ')' || c == '}')
                    depth = Math.max(0, depth - 1);
                if (c == '\n' || (c == ';' && depth == 0)) {
                    ret.add(cur.toString());
                    cur.setLength(0);
                    continue;
                }
            }
            if (c != '\r')
                cur.append(c);
        }
        ret.add(cur.toString());
        return ret;
    }

    private static boolean startsWithWord(String s, String word) {
        return s.startsWith(word) && (s.length() == word.length() || !Character.isLetterOrDigit(s.charAt(word.length())));
    }

    private static final class EdgeSpec {
        final boolean arrow, dotted, thick;
        final String label;

        EdgeSpec(boolean arrow, boolean dotted, boolean thick, String label) {
            this.arrow = arrow;
            this.dotted = dotted;
            this.thick = thick;
            this.label = label;
        }
    }

    /** Scanner over one statement: {@code nodes (edge nodes)*}. */
    private static final class Cursor {
        private final String s;
        private int i;

        Cursor(String s) {
            this.s = s;
        }

        void statement(Graph g) {
            List<Node> prev = nodeGroup(g);
            skipWs();
            while (i < s.length()) {
                EdgeSpec op = edgeOp();
                List<Node> next = nodeGroup(g);
                for (Node a : prev)
                    for (Node b : next)
                        g.addEdge(a, b, op);
                prev = next;
                skipWs();
            }
        }

        private void skipWs() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i)))
                i++;
        }

        private List<Node> nodeGroup(Graph g) {
            List<Node> list = new ArrayList<>();
            while (true) {
                list.add(nodeRef(g));
                skipWs();
                if (i < s.length() && s.charAt(i) == '&') {
                    i++;
                    skipWs();
                    continue;
                }
                return list;
            }
        }

        private Node nodeRef(Graph g) {
            skipWs();
            int start = i;
            while (i < s.length() && (Character.isLetterOrDigit(s.charAt(i)) || s.charAt(i) == '_'))
                i++;
            if (start == i)
                throw new IllegalArgumentException("node expected at column " + (i + 1) + " in: " + s);
            Node n = g.node(s.substring(start, i));
            for (Object[] o : OPENERS) {
                String open = (String) o[0], close = (String) o[1];
                if (s.startsWith(open, i)) {
                    int end = s.indexOf(close, i + open.length());
                    if (end < 0)
                        throw new IllegalArgumentException("unterminated " + open + " for node " + n.id + " in: " + s);
                    n.label = cleanLabel(s.substring(i + open.length(), end));
                    n.shape = (Shape) o[2];
                    i = end + close.length();
                    break;
                }
            }
            return n;
        }

        private EdgeSpec edgeOp() {
            skipWs();
            int start = i;
            while (i < s.length() && "-.=>xo".indexOf(s.charAt(i)) >= 0)
                i++;
            String op = s.substring(start, i);
            if (op.isEmpty() || (!op.contains("-") && !op.contains("=")))
                throw new IllegalArgumentException("edge expected at column " + (start + 1) + " in: " + s);
            boolean dotted = op.contains("."), thick = op.contains("=");
            boolean arrow;
            String label = null;
            if (op.endsWith(">") || op.endsWith("x") || op.endsWith("o") || op.matches("-{3,}|-\\.+-|={3,}")) {
                arrow = !op.matches("-{3,}|-\\.+-|={3,}");
            } else {
                // "-- text -->", "-. text .->", "== text ==>"
                Matcher m = TEXT_ARROW.matcher(s);
                m.region(i, s.length());
                if (!m.lookingAt())
                    throw new IllegalArgumentException("unterminated edge text at column " + (i + 1) + " in: " + s);
                label = cleanLabel(m.group(1));
                String close = m.group(2);
                arrow = close.endsWith(">");
                dotted |= close.contains(".");
                thick |= close.contains("=");
                i = m.end();
            }
            skipWs();
            if (i < s.length() && s.charAt(i) == '|') {
                int end = s.indexOf('|', i + 1);
                if (end < 0)
                    throw new IllegalArgumentException("unterminated |label| at column " + (i + 1) + " in: " + s);
                label = cleanLabel(s.substring(i + 1, end));
                i = end + 1;
            }
            return new EdgeSpec(arrow, dotted, thick, label != null && label.isEmpty() ? null : label);
        }
    }

    private static String cleanLabel(String raw) {
        String t = raw.trim();
        if (t.length() >= 2 && t.startsWith("\"") && t.endsWith("\""))
            t = t.substring(1, t.length() - 1);
        t = BR.matcher(t).replaceAll("\n");
        t = TAG.matcher(t).replaceAll("");
        Matcher m = ENTITY.matcher(t);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String e = m.group(1);
            String rep;
            switch (e) {
                case "amp": rep = "&"; break;
                case "lt": rep = "<"; break;
                case "gt": rep = ">"; break;
                case "quot": rep = "\""; break;
                case "apos": rep = "'"; break;
                case "nbsp": rep = " "; break;
                default:
                    try {
                        int cp = e.startsWith("#x") ? Integer.parseInt(e.substring(2), 16) : Integer.parseInt(e.substring(1));
                        rep = new String(Character.toChars(cp));
                    } catch (RuntimeException ex) {
                        rep = m.group();
                    }
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(rep));
        }
        m.appendTail(sb);
        String[] lines = sb.toString().split("\n");
        StringBuilder out = new StringBuilder();
        for (String line : lines) {
            if (out.length() > 0)
                out.append('\n');
            out.append(line.trim());
        }
        return out.toString();
    }

    private static String shapeOpen(Shape s) {
        for (Object[] o : OPENERS)
            if (o[2] == s)
                return (String) o[0];
        return "[";
    }

    private static String shapeClose(Shape s) {
        for (Object[] o : OPENERS)
            if (o[2] == s)
                return (String) o[1];
        return "]";
    }

    // ---------------------------------------------------------------- layout

    private static FontMetrics metrics(Font font) {
        Graphics2D g = new BufferedImage(1, 1, BufferedImage.TYPE_INT_ARGB).createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_FRACTIONALMETRICS, RenderingHints.VALUE_FRACTIONALMETRICS_ON);
            return g.getFontMetrics(font);
        } finally {
            g.dispose();
        }
    }

    private static void layout(Graph g) {
        List<Node> nodes = new ArrayList<>(g.nodes.values());
        measure(nodes);
        for (Node n : nodes) {
            n.mainSize = g.vertical ? n.h : n.w;
            n.crossSize = g.vertical ? n.w : n.h;
        }
        markBackEdges(nodes);
        List<List<Node>> layers = assignLayers(nodes);
        orderLayers(layers);
        position(layers);

        float totalMain = 0, totalCross = 0;
        for (Node n : nodes) {
            totalMain = Math.max(totalMain, n.main + n.mainSize / 2);
            totalCross = Math.max(totalCross, n.cross + n.crossSize / 2);
        }
        totalMain += MARGIN;
        totalCross += MARGIN;
        for (Edge e : g.edges)
            if (e.back && e.from != e.to) {
                totalCross += BACK_EDGE_ROOM;
                break;
            }
        for (Node n : nodes) {
            float main = g.reversed ? totalMain - n.main : n.main;
            if (g.vertical) {
                n.x = n.cross - n.w / 2;
                n.y = main - n.h / 2;
            } else {
                n.x = main - n.w / 2;
                n.y = n.cross - n.h / 2;
            }
        }
        g.width = g.vertical ? totalCross : totalMain;
        g.height = g.vertical ? totalMain : totalCross;
    }

    private static void measure(List<Node> nodes) {
        FontMetrics fm = metrics(FONT);
        for (Node n : nodes) {
            n.label = wrap(n.label, fm);
            String[] lines = n.label.split("\n");
            float tw = 0;
            for (String line : lines)
                tw = Math.max(tw, (float) fm.getStringBounds(line, null).getWidth());
            float th = lines.length * fm.getHeight();
            float w = tw + 2 * PAD_X, h = th + 2 * PAD_Y;
            switch (n.shape) {
                case DIAMOND:
                    w = w * 1.5f;
                    h = h * 1.7f;
                    break;
                case CIRCLE:
                    w = h = Math.max(w, h) + 8;
                    break;
                case HEXAGON:
                    w += 24;
                    break;
                case STADIUM:
                    w += h / 2;
                    break;
                case PARALLELOGRAM:
                    w += 20;
                    break;
                case ASYMMETRIC:
                    w += 12;
                    break;
                case CYLINDER:
                    h += 16;
                    break;
                case SUBROUTINE:
                    w += 16;
                    break;
                default:
                    break;
            }
            n.w = w;
            n.h = h;
        }
    }

    /** Depth-first search; edges into a node still on the stack are back edges. */
    private static void markBackEdges(List<Node> nodes) {
        Map<Node, Integer> state = new IdentityHashMap<>();
        for (Node n : nodes)
            if (state.get(n) == null)
                dfs(n, state);
    }

    private static void dfs(Node n, Map<Node, Integer> state) {
        state.put(n, 1);
        for (Edge e : n.out) {
            Integer s = state.get(e.to);
            if (s == null)
                dfs(e.to, state);
            else if (s == 1)
                e.back = true;
        }
        state.put(n, 2);
    }

    /** Longest path from the sources over forward edges. */
    private static List<List<Node>> assignLayers(List<Node> nodes) {
        boolean changed = true;
        for (Node n : nodes)
            n.layer = 0;
        int guard = nodes.size() + 1;
        while (changed && guard-- > 0) {
            changed = false;
            for (Node n : nodes)
                for (Edge e : n.out)
                    if (!e.back && e.to.layer < n.layer + 1) {
                        e.to.layer = n.layer + 1;
                        changed = true;
                    }
        }
        int max = 0;
        for (Node n : nodes)
            max = Math.max(max, n.layer);
        List<List<Node>> layers = new ArrayList<>();
        for (int l = 0; l <= max; l++)
            layers.add(new ArrayList<Node>());
        for (Node n : nodes)
            layers.get(n.layer).add(n);
        for (List<Node> layer : layers)
            for (int i = 0; i < layer.size(); i++)
                layer.get(i).order = i;
        return layers;
    }

    /** Barycenter sweeps to reduce crossings. */
    private static void orderLayers(List<List<Node>> layers) {
        for (int iter = 0; iter < 4; iter++) {
            boolean down = iter % 2 == 0;
            if (down)
                for (int l = 1; l < layers.size(); l++)
                    sortByBarycenter(layers.get(l), true);
            else
                for (int l = layers.size() - 2; l >= 0; l--)
                    sortByBarycenter(layers.get(l), false);
        }
    }

    private static void sortByBarycenter(List<Node> layer, boolean usePredecessors) {
        final Map<Node, Float> bary = new IdentityHashMap<>();
        for (Node n : layer) {
            float sum = 0;
            int count = 0;
            for (Edge e : usePredecessors ? n.in : n.out) {
                if (e.back)
                    continue;
                sum += usePredecessors ? e.from.order : e.to.order;
                count++;
            }
            bary.put(n, count == 0 ? n.order : sum / count);
        }
        Collections.sort(layer, new Comparator<Node>() {
            @Override
            public int compare(Node a, Node b) {
                return Float.compare(bary.get(a), bary.get(b));
            }
        });
        for (int i = 0; i < layer.size(); i++)
            layer.get(i).order = i;
    }

    /** Layer positions along the main axis, node positions along the cross axis. */
    private static void position(List<List<Node>> layers) {
        float pos = MARGIN;
        for (List<Node> layer : layers) {
            float size = 0;
            for (Node n : layer)
                size = Math.max(size, n.mainSize);
            for (Node n : layer)
                n.main = pos + size / 2;
            pos += size + LAYER_GAP;
        }
        // initial: pack each layer and center it
        float maxWidth = 0;
        for (List<Node> layer : layers)
            maxWidth = Math.max(maxWidth, packedWidth(layer));
        for (List<Node> layer : layers) {
            float c = MARGIN + (maxWidth - packedWidth(layer)) / 2;
            for (Node n : layer) {
                n.cross = c + n.crossSize / 2;
                c += n.crossSize + NODE_GAP;
            }
        }
        // relax: every node moves to the mean of its neighbours (both directions), then
        // overlaps in the layer are pushed apart symmetrically so parents end up centred
        // over their children and siblings spread evenly around them
        for (int round = 0; round < 12; round++) {
            boolean down = round % 2 == 0;
            for (int i = 0; i < layers.size(); i++) {
                List<Node> layer = layers.get(down ? i : layers.size() - 1 - i);
                for (Node n : layer) {
                    float sum = 0;
                    int count = 0;
                    for (Edge e : n.in)
                        if (!e.back) {
                            sum += e.from.cross;
                            count++;
                        }
                    for (Edge e : n.out)
                        if (!e.back) {
                            sum += e.to.cross;
                            count++;
                        }
                    if (count > 0)
                        n.cross = sum / count;
                }
                resolveOverlaps(layer);
            }
        }
        // shift everything so the leftmost node starts at the margin
        float min = Float.MAX_VALUE;
        for (List<Node> layer : layers)
            for (Node n : layer)
                min = Math.min(min, n.cross - n.crossSize / 2);
        float shift = MARGIN - min;
        for (List<Node> layer : layers)
            for (Node n : layer)
                n.cross += shift;
    }

    private static float packedWidth(List<Node> layer) {
        float w = 0;
        for (Node n : layer)
            w += n.crossSize + NODE_GAP;
        return Math.max(0, w - NODE_GAP);
    }

    /** Keeps the layer's order and pushes overlapping neighbours apart around their midpoint. */
    private static void resolveOverlaps(List<Node> layer) {
        for (int iter = 0; iter < 32; iter++) {
            boolean moved = false;
            for (int i = 0; i + 1 < layer.size(); i++) {
                Node a = layer.get(i), b = layer.get(i + 1);
                float overlap = (a.cross + a.crossSize / 2 + NODE_GAP) - (b.cross - b.crossSize / 2);
                if (overlap > 0.01f) {
                    a.cross -= overlap / 2;
                    b.cross += overlap / 2;
                    moved = true;
                }
            }
            if (!moved)
                return;
        }
    }

    /** Word-wraps lines wider than {@link #MAX_LABEL_WIDTH}. */
    private static String wrap(String label, FontMetrics fm) {
        StringBuilder out = new StringBuilder();
        for (String line : label.split("\n")) {
            if (out.length() > 0)
                out.append('\n');
            if (fm.getStringBounds(line, null).getWidth() <= MAX_LABEL_WIDTH) {
                out.append(line);
                continue;
            }
            StringBuilder cur = new StringBuilder();
            for (String word : line.split(" ")) {
                String candidate = cur.length() == 0 ? word : cur + " " + word;
                if (cur.length() > 0 && fm.getStringBounds(candidate, null).getWidth() > MAX_LABEL_WIDTH) {
                    out.append(cur).append('\n');
                    cur.setLength(0);
                    cur.append(word);
                } else {
                    cur.setLength(0);
                    cur.append(candidate);
                }
            }
            out.append(cur);
        }
        return out.toString();
    }

    // -------------------------------------------------------------- painting

    private static void paintNode(Graphics2D g2, Node n) {
        java.awt.Shape shape = shapeOf(n);
        g2.setColor(NODE_FILL);
        g2.fill(shape);
        g2.setColor(NODE_STROKE);
        g2.setStroke(new BasicStroke(1.5f));
        g2.draw(shape);
        if (n.shape == Shape.SUBROUTINE) {
            g2.draw(new java.awt.geom.Line2D.Float(n.x + 8, n.y, n.x + 8, n.y + n.h));
            g2.draw(new java.awt.geom.Line2D.Float(n.x + n.w - 8, n.y, n.x + n.w - 8, n.y + n.h));
        } else if (n.shape == Shape.CYLINDER) {
            g2.draw(new java.awt.geom.Arc2D.Float(n.x, n.y, n.w, 16, 180, 180, java.awt.geom.Arc2D.OPEN));
        }
        g2.setColor(TEXT);
        g2.setFont(FONT);
        FontMetrics fm = g2.getFontMetrics();
        String[] lines = n.label.split("\n");
        float lineH = fm.getHeight();
        float top = n.y + (n.h - lines.length * lineH) / 2 + fm.getAscent();
        if (n.shape == Shape.CYLINDER)
            top += 4;
        for (int i = 0; i < lines.length; i++) {
            float tw = (float) fm.getStringBounds(lines[i], g2).getWidth();
            g2.drawString(lines[i], n.x + (n.w - tw) / 2, top + i * lineH);
        }
    }

    private static java.awt.Shape shapeOf(Node n) {
        float x = n.x, y = n.y, w = n.w, h = n.h, cx = x + w / 2, cy = y + h / 2;
        Path2D.Float p = new Path2D.Float();
        switch (n.shape) {
            case ROUND:
                return new RoundRectangle2D.Float(x, y, w, h, 12, 12);
            case STADIUM:
                return new RoundRectangle2D.Float(x, y, w, h, h, h);
            case CIRCLE:
                return new Ellipse2D.Float(x, y, w, h);
            case DIAMOND:
                p.moveTo(cx, y);
                p.lineTo(x + w, cy);
                p.lineTo(cx, y + h);
                p.lineTo(x, cy);
                p.closePath();
                return p;
            case HEXAGON: {
                float c = Math.min(h / 2, 14);
                p.moveTo(x + c, y);
                p.lineTo(x + w - c, y);
                p.lineTo(x + w, cy);
                p.lineTo(x + w - c, y + h);
                p.lineTo(x + c, y + h);
                p.lineTo(x, cy);
                p.closePath();
                return p;
            }
            case PARALLELOGRAM:
                p.moveTo(x + 10, y);
                p.lineTo(x + w, y);
                p.lineTo(x + w - 10, y + h);
                p.lineTo(x, y + h);
                p.closePath();
                return p;
            case ASYMMETRIC:
                p.moveTo(x, y);
                p.lineTo(x + w, y);
                p.lineTo(x + w, y + h);
                p.lineTo(x, y + h);
                p.lineTo(x + 10, cy);
                p.closePath();
                return p;
            case CYLINDER: {
                p.moveTo(x, y + 8);
                p.lineTo(x, y + h - 8);
                p.curveTo(x, y + h + 3, x + w, y + h + 3, x + w, y + h - 8);
                p.lineTo(x + w, y + 8);
                p.curveTo(x + w, y - 3, x, y - 3, x, y + 8);
                p.closePath();
                return p;
            }
            default:
                return new Rectangle2D.Float(x, y, w, h);
        }
    }

    private static void paintEdge(Graphics2D g2, Graph g, Edge e) {
        Node a = e.from, b = e.to;
        CubicCurve2D.Float curve = new CubicCurve2D.Float();
        if (a == b) {
            // self loop on the right/bottom side
            float x = a.x + a.w, y = a.y + a.h / 2;
            curve.setCurve(x, y - 8, x + 40, y - 30, x + 40, y + 30, x, y + 8);
        } else if (a.layer == b.layer) {
            Point2D.Float p1 = anchorToward(a, b), p2 = anchorToward(b, a);
            curve.setCurve(p1.x, p1.y, p1.x, p1.y, p2.x, p2.y, p2.x, p2.y);
        } else if (!e.back) {
            // leave a and enter b where the centre-to-centre line crosses their boxes, with
            // tangents along the layer axis: Mermaid's look
            Point2D.Float p1 = anchorToward(a, b), p2 = anchorToward(b, a);
            {
                float d = g.vertical ? (p2.y - p1.y) / 2 : (p2.x - p1.x) / 2;
                if (g.vertical)
                    curve.setCurve(p1.x, p1.y, p1.x, p1.y + d, p2.x, p2.y - d, p2.x, p2.y);
                else
                    curve.setCurve(p1.x, p1.y, p1.x + d, p1.y, p2.x - d, p2.y, p2.x, p2.y);
            }
        } else {
            // back edge (b in an earlier layer): leave a at its near side, enter b at its far
            // side and loop around the side so it does not run through the nodes in between
            Point2D.Float p1 = mainAnchor(g, a, false), p2 = mainAnchor(g, b, true);
            {
                // farthest cross-axis extent of the nodes in the layers the edge spans; the
                // cubic's control points sit beyond it so the loop clears them
                int lo = Math.min(a.layer, b.layer), hi = Math.max(a.layer, b.layer);
                float far = 0;
                for (Node n : g.nodes.values())
                    if (n.layer >= lo && n.layer <= hi)
                        far = Math.max(far, g.vertical ? n.x + n.w : n.y + n.h);
                float ctrl = far + BACK_EDGE_ROOM * 0.9f;
                // pull the control points past the target so the curve itself reaches "far"
                float reach = ctrl + (ctrl - (g.vertical ? Math.max(p1.x, p2.x) : Math.max(p1.y, p2.y))) * 0.35f;
                if (g.vertical)
                    curve.setCurve(p1.x, p1.y, reach, p1.y - 30, reach, p2.y + 30, p2.x, p2.y);
                else
                    curve.setCurve(p1.x, p1.y, p1.x - 30, reach, p2.x + 30, reach, p2.x, p2.y);
            }
        }

        g2.setColor(EDGE);
        float width = e.thick ? 3f : 1.4f;
        g2.setStroke(e.dotted
                ? new BasicStroke(width, BasicStroke.CAP_BUTT, BasicStroke.JOIN_ROUND, 10f, new float[]{4f, 4f}, 0f)
                : new BasicStroke(width, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g2.draw(curve);

        if (e.arrow) {
            Point2D.Float tip = pointAt(curve, 1f), back = pointAt(curve, 0.95f);
            double ang = Math.atan2(tip.y - back.y, tip.x - back.x);
            Path2D.Float head = new Path2D.Float();
            head.moveTo(tip.x, tip.y);
            head.lineTo(tip.x - ARROW * Math.cos(ang - 0.45), tip.y - ARROW * Math.sin(ang - 0.45));
            head.lineTo(tip.x - ARROW * Math.cos(ang + 0.45), tip.y - ARROW * Math.sin(ang + 0.45));
            head.closePath();
            g2.setStroke(new BasicStroke(1f));
            g2.fill(head);
        }

        if (e.label != null) {
            Point2D.Float mid = pointAt(curve, 0.5f);
            g2.setFont(EDGE_FONT);
            FontMetrics fm = g2.getFontMetrics();
            String[] lines = e.label.split("\n");
            float tw = 0;
            for (String line : lines)
                tw = Math.max(tw, (float) fm.getStringBounds(line, g2).getWidth());
            float th = lines.length * fm.getHeight();
            float bx = mid.x - tw / 2 - 4, by = mid.y - th / 2 - 2;
            g2.setColor(EDGE_LABEL_BG);
            g2.fill(new RoundRectangle2D.Float(bx, by, tw + 8, th + 4, 4, 4));
            g2.setColor(TEXT);
            for (int i = 0; i < lines.length; i++) {
                float lw = (float) fm.getStringBounds(lines[i], g2).getWidth();
                g2.drawString(lines[i], mid.x - lw / 2, by + 2 + fm.getAscent() + i * fm.getHeight());
            }
        }
    }

    /** Anchor on the main-axis side of {@code n}: bottom/right when {@code far}, top/left otherwise (before reversal). */
    private static Point2D.Float mainAnchor(Graph g, Node n, boolean far) {
        boolean atEnd = far != g.reversed;
        if (g.vertical)
            return new Point2D.Float(n.x + n.w / 2, atEnd ? n.y + n.h : n.y);
        return new Point2D.Float(atEnd ? n.x + n.w : n.x, n.y + n.h / 2);
    }

    /** Point on the box of {@code n} where the line from its centre to {@code other}'s centre leaves it. */
    private static Point2D.Float anchorToward(Node n, Node other) {
        float cx = n.x + n.w / 2, cy = n.y + n.h / 2;
        float dx = other.x + other.w / 2 - cx, dy = other.y + other.h / 2 - cy;
        if (Math.abs(dx) < 0.001f && Math.abs(dy) < 0.001f)
            return new Point2D.Float(cx, n.y + n.h);
        float tx = Math.abs(dx) < 0.001f ? Float.MAX_VALUE : (n.w / 2) / Math.abs(dx);
        float ty = Math.abs(dy) < 0.001f ? Float.MAX_VALUE : (n.h / 2) / Math.abs(dy);
        float t = Math.min(tx, ty);
        return new Point2D.Float(cx + dx * t, cy + dy * t);
    }

    private static Point2D.Float pointAt(CubicCurve2D.Float c, float t) {
        float u = 1 - t;
        float x = u * u * u * c.x1 + 3 * u * u * t * c.ctrlx1 + 3 * u * t * t * c.ctrlx2 + t * t * t * c.x2;
        float y = u * u * u * c.y1 + 3 * u * u * t * c.ctrly1 + 3 * u * t * t * c.ctrly2 + t * t * t * c.y2;
        return new Point2D.Float(x, y);
    }
}
