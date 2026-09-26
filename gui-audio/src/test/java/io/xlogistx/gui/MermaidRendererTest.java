package io.xlogistx.gui;

import org.junit.jupiter.api.Test;

import java.awt.image.BufferedImage;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class MermaidRendererTest {

    private static final String HKDF =
            "flowchart TD\n" +
            "    A[Raw secret<br/>e.g. handshake result] --> C\n" +
            "    B[Salt<br/>optional, public] --> C\n" +
            "    C[Extract: HMAC salt, secret] --> D[PRK<br/>one clean 32-byte key]\n" +
            "    D --> E[Expand: HMAC PRK, label + counter]\n" +
            "    E --> F[Client write key]\n" +
            "    E --> G[Server write key]\n" +
            "    E --> H[IVs, further keys]\n";

    private static final String TLS =
            "flowchart TD\n" +
            "    X[X25519 secret] --> CAT[Concatenate: raw secret]\n" +
            "    K[ML-KEM secret] --> CAT\n" +
            "    CAT --> EX[Extract<br/>salt = previous secret]\n" +
            "    EX --> MS[Master secret PRK]\n" +
            "    MS --> CA[\"Expand c ap traffic<br/>+ transcript hash\"]\n" +
            "    MS --> SA[\"Expand s ap traffic<br/>+ transcript hash\"]\n" +
            "    CA --> CK[\"Client key + IV<br/>labels key, iv\"]\n" +
            "    SA --> SK[\"Server key + IV<br/>labels key, iv\"]\n" +
            "    CK --> CN[nonce = IV xor seq]\n" +
            "    SK --> SN[nonce = IV xor seq]\n" +
            "    CN --> CR[Client to server records]\n" +
            "    SN --> SR[Server to client records]\n";

    @Test
    public void parsesNodesShapesAndLabels() {
        MermaidRenderer.Graph g = MermaidRenderer.parse(HKDF);
        assertTrue(g.isVertical());
        assertFalse(g.isReversed());
        assertEquals(8, g.getNodes().size());
        assertEquals(7, g.getEdges().size());
        MermaidRenderer.Node a = g.getNode("A");
        assertEquals("Raw secret\ne.g. handshake result", a.getLabel(), "<br/> becomes a line break");
        assertEquals(MermaidRenderer.Shape.RECT, a.getShape());
        // C is referenced before it is defined: the later definition supplies the label
        assertEquals("Extract: HMAC salt, secret", g.getNode("C").getLabel());
        assertEquals("C", g.getEdges().get(0).getTo().getId());
        assertTrue(g.getEdges().get(0).hasArrow());
    }

    @Test
    public void parsesQuotedLabelsEntitiesAndTags() {
        MermaidRenderer.Graph g = MermaidRenderer.parse(TLS);
        assertEquals(13, g.getNodes().size());
        assertEquals("Expand c ap traffic\n+ transcript hash", g.getNode("CA").getLabel(), "quotes stripped");
        MermaidRenderer.Graph e = MermaidRenderer.parse("graph LR\n a[\"Tom &amp; Jerry <b>bold</b> &#65;\"] --> b");
        assertFalse(e.isVertical());
        assertEquals("Tom & Jerry bold A", e.getNode("a").getLabel());
    }

    @Test
    public void parsesAllShapesEdgeStylesChainsAndFans() {
        MermaidRenderer.Graph g = MermaidRenderer.parse(
                "flowchart LR\n" +
                "  r[rect] --> o(round) --> s([stadium]) --> u[[sub]]\n" +
                "  c((circle)) -.-> d{diamond} ==> h{{hex}} --- p[/para/]\n" +
                "  y[(db)] -->|labelled| z>flag]\n" +
                "  r -- text --> c\n" +
                "  a1 & a2 --> b1 & b2;\n" +
                "  %% comment line\n" +
                "  subgraph grp [Group]\n" +
                "    q[in group]\n" +
                "  end\n" +
                "  classDef x fill:#f00\n" +
                "  style r fill:#0f0\n");
        assertEquals(MermaidRenderer.Shape.ROUND, g.getNode("o").getShape());
        assertEquals(MermaidRenderer.Shape.STADIUM, g.getNode("s").getShape());
        assertEquals(MermaidRenderer.Shape.SUBROUTINE, g.getNode("u").getShape());
        assertEquals(MermaidRenderer.Shape.CIRCLE, g.getNode("c").getShape());
        assertEquals(MermaidRenderer.Shape.DIAMOND, g.getNode("d").getShape());
        assertEquals(MermaidRenderer.Shape.HEXAGON, g.getNode("h").getShape());
        assertEquals(MermaidRenderer.Shape.PARALLELOGRAM, g.getNode("p").getShape());
        assertEquals(MermaidRenderer.Shape.CYLINDER, g.getNode("y").getShape());
        assertEquals(MermaidRenderer.Shape.ASYMMETRIC, g.getNode("z").getShape());
        assertEquals("in group", g.getNode("q").getLabel());
        assertNull(g.getNode("grp"), "subgraph line is skipped");

        List<MermaidRenderer.Edge> edges = g.getEdges();
        MermaidRenderer.Edge dotted = find(edges, "c", "d");
        assertTrue(dotted.isDotted() && dotted.hasArrow());
        MermaidRenderer.Edge thick = find(edges, "d", "h");
        assertTrue(thick.isThick() && thick.hasArrow());
        MermaidRenderer.Edge line = find(edges, "h", "p");
        assertFalse(line.hasArrow());
        assertEquals("labelled", find(edges, "y", "z").getLabel());
        assertEquals("text", find(edges, "r", "c").getLabel());
        assertNotNull(find(edges, "a1", "b1"));
        assertNotNull(find(edges, "a1", "b2"));
        assertNotNull(find(edges, "a2", "b1"));
        assertNotNull(find(edges, "a2", "b2"));
    }

    @Test
    public void rejectsWhatItCannotDraw() {
        assertFalse(MermaidRenderer.isFlowchart("sequenceDiagram\n A->>B: hi"));
        assertFalse(MermaidRenderer.isFlowchart(""));
        assertFalse(MermaidRenderer.isFlowchart(null));
        assertTrue(MermaidRenderer.isFlowchart("%% c\n\n graph TD\n a"));
        assertThrows(IllegalArgumentException.class, () -> MermaidRenderer.parse("sequenceDiagram\n A->>B: hi"));
        assertThrows(IllegalArgumentException.class, () -> MermaidRenderer.parse("flowchart TD\n a[unterminated --> b"));
        assertThrows(IllegalArgumentException.class, () -> MermaidRenderer.parse("flowchart TD\n a ~~> b"));
        assertThrows(IllegalArgumentException.class, () -> MermaidRenderer.parse("flowchart TD\n"));
        assertThrows(NullPointerException.class, () -> MermaidRenderer.parse(null));
    }

    @Test
    public void layoutIsLayeredAndRenders() {
        MermaidRenderer.Graph g = MermaidRenderer.parse(HKDF);
        BufferedImage img = MermaidRenderer.render(g, 1f);
        assertTrue(img.getWidth() > 200 && img.getHeight() > 200, img.getWidth() + "x" + img.getHeight());
        assertEquals(Math.round(g.getWidth()), img.getWidth());

        // sources on layer 0, the fan-out on the last layer, every node inside the image
        assertEquals(0, g.getNode("A").getLayer());
        assertEquals(0, g.getNode("B").getLayer());
        assertEquals(1, g.getNode("C").getLayer());
        assertEquals(4, g.getNode("F").getLayer());
        for (MermaidRenderer.Node n : g.getNodes()) {
            java.awt.geom.Rectangle2D.Float b = n.getBounds();
            assertTrue(b.x >= 0 && b.y >= 0 && b.x + b.width <= g.getWidth() && b.y + b.height <= g.getHeight(), n + " " + b);
        }
        // a node on a later layer sits below one on an earlier layer (TD)
        assertTrue(g.getNode("F").getBounds().y > g.getNode("A").getBounds().y);
        // nodes of one layer do not overlap
        java.awt.geom.Rectangle2D.Float f = g.getNode("F").getBounds(), gg = g.getNode("G").getBounds();
        assertFalse(f.intersects(gg));

        // something got painted: node fill and text pixels
        assertTrue(count(img, 0xEDEDEA) > 1000, "node fill pixels");
        assertTrue(count(img, 0x333333) > 50, "text/edge pixels");

        // scale 2 doubles the pixel size
        BufferedImage big = MermaidRenderer.render(HKDF, 2f);
        assertEquals(img.getWidth() * 2, big.getWidth());
    }

    @Test
    public void rendersEveryDirectionAndBackEdges() {
        for (String dir : new String[]{"TD", "TB", "BT", "LR", "RL"}) {
            MermaidRenderer.Graph g = MermaidRenderer.parse("flowchart " + dir + "\n a --> b --> c --> a\n c -->|again| b\n b --> b");
            BufferedImage img = MermaidRenderer.render(g, 1f);
            assertTrue(img.getWidth() > 50 && img.getHeight() > 50, dir);
            assertTrue(count(img, 0xEDEDEA) > 100, dir);
            if (g.isVertical())
                assertTrue(g.getHeight() > g.getWidth() * 0.8f, dir + " should stack vertically");
            else
                assertTrue(g.getWidth() > g.getHeight(), dir + " should stack horizontally");
        }
        MermaidRenderer.Graph bt = MermaidRenderer.parse("flowchart BT\n a --> b");
        MermaidRenderer.render(bt, 1f);
        assertTrue(bt.getNode("b").getBounds().y < bt.getNode("a").getBounds().y, "BT: later layer is above");
    }

    @Test
    public void pngEncodes() throws Exception {
        byte[] png = MermaidRenderer.renderPNG(TLS, 2f);
        assertTrue(png.length > 1000);
        assertEquals((byte) 0x89, png[0]);
        assertEquals('P', png[1]);
    }

    private static MermaidRenderer.Edge find(List<MermaidRenderer.Edge> edges, String from, String to) {
        for (MermaidRenderer.Edge e : edges)
            if (e.getFrom().getId().equals(from) && e.getTo().getId().equals(to))
                return e;
        return null;
    }

    private static int count(BufferedImage img, int rgb) {
        int n = 0;
        for (int y = 0; y < img.getHeight(); y++)
            for (int x = 0; x < img.getWidth(); x++)
                if ((img.getRGB(x, y) & 0xFFFFFF) == rgb)
                    n++;
        return n;
    }
}
