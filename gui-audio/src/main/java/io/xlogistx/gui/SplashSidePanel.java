package io.xlogistx.gui;

import net.miginfocom.swing.MigLayout;

import javax.swing.Icon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Color;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;

/**
 * The dark brand half of a sign-in or welcome screen: a brand line at the top, a large title,
 * a tagline, a list of check-marked points, and a muted footer line. All copy is passed in;
 * the panel knows nothing about the application showing it. Text wraps to the panel's width
 * ({@link WrapLabel}s whose wrap width follows {@link #doLayout()}).
 */
public class SplashSidePanel extends JPanel {

    private static final int DEFAULT_BACKGROUND = 0x17171C;
    private static final int INSET_X = 56;
    private static final int POINT_INDENT = 28; // check icon + gap

    private final JPanel points = new JPanel(new MigLayout("insets 0, wrap 1, gapy 10, fillx", "[grow,fill]"));
    private final WrapLabel title;
    private final WrapLabel tagline;
    private final WrapLabel footer;
    private final List<WrapLabel> pointLabels = new ArrayList<>();
    private final Color checkColor = new Color(0xA9A8F0);

    /**
     * @param brandIcon  a small icon before the brand name, or null
     * @param brand      the product name shown at the top
     * @param titleText  the large heading
     * @param taglineText one or two sentences under it, or null
     * @param pointList  check-marked promises or features, may be empty
     * @param footerText a muted line at the bottom (version, platform), or null
     */
    public SplashSidePanel(Icon brandIcon, String brand, String titleText, String taglineText, List<String> pointList, String footerText) {
        super(new MigLayout("insets 48 " + INSET_X + " 40 " + INSET_X + ", wrap 1, gapy 0, fillx, hidemode 3",
                "[grow,fill]", "[]push[]16[]24[]push[]"));
        setBackground(new Color(DEFAULT_BACKGROUND));

        JLabel brandLabel = new JLabel(brand, brandIcon, JLabel.LEFT);
        brandLabel.setIconTextGap(12);
        brandLabel.setFont(UITokens.font(Font.BOLD, 5f));
        brandLabel.setForeground(Color.WHITE);
        add(brandLabel);

        title = text(titleText, UITokens.font(Font.BOLD, 20f), Color.WHITE);
        add(title, "growx, wmin 0");

        tagline = text(taglineText != null ? taglineText : "", UITokens.font(Font.PLAIN, 2f), new Color(0xC9C9D2));
        tagline.setVisible(taglineText != null && !taglineText.isEmpty());
        add(tagline, "growx, wmin 0");

        points.setOpaque(false);
        setPoints(pointList);
        add(points, "growx, wmin 0");

        footer = text(footerText != null ? footerText : "", UITokens.mono(-1f), new Color(0x8A8A96));
        footer.setVisible(footerText != null && !footerText.isEmpty());
        add(footer, "growx, wmin 0");
    }

    /** Replaces the check-marked points. */
    public void setPoints(List<String> pointList) {
        points.removeAll();
        pointLabels.clear();
        if (pointList != null) {
            for (String p : pointList) {
                JPanel row = new JPanel(new MigLayout("insets 0, gapx 12", "[]0[grow,fill]"));
                row.setOpaque(false);
                JLabel check = new JLabel(IconUtil.svgIcon("io/xlogistx/gui/icons/check.svg", 16, checkColor));
                row.add(check, "aligny top, gaptop 2");
                WrapLabel label = text(p, UITokens.font(Font.PLAIN, 0.5f), new Color(0xE6E6EC));
                pointLabels.add(label);
                row.add(label, "growx, wmin 0");
                points.add(row, "growx");
            }
        }
        points.revalidate();
        points.repaint();
    }

    /** Replaces the footer line. */
    public void setFooter(String footerText) {
        footer.setText(footerText != null ? footerText : "");
        footer.setVisible(footerText != null && !footerText.isEmpty());
    }

    @Override
    public void doLayout() {
        int w = getWidth() - 2 * INSET_X;
        if (w >= 40) {
            title.setWrapWidth(w);
            tagline.setWrapWidth(w);
            footer.setWrapWidth(w);
            for (WrapLabel l : pointLabels) l.setWrapWidth(w - POINT_INDENT);
        }
        super.doLayout();
    }

    private static WrapLabel text(String s, Font font, Color color) {
        WrapLabel l = new WrapLabel(s);
        l.setFont(font);
        l.setForeground(color);
        return l;
    }
}
