package io.xlogistx.gui;

import com.formdev.flatlaf.FlatClientProperties;
import net.miginfocom.swing.MigLayout;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.util.ArrayList;
import java.util.List;

/**
 * Numbered steps down the page, each with a title, a description and a body. A step is
 * {@link State#TODO}, {@link State#ACTIVE} or {@link State#DONE}; a done step collapses its body
 * to a one-line summary with an optional <b>Change</b> button that reopens it. A rail joins the
 * step markers.
 * <pre>
 * StepperPanel steps = new StepperPanel();
 * int open = steps.addStep("Open store", "Where NoSneak keeps its data", openForm);
 * int sign = steps.addStep("Sign in", "Your account in this store", signInForm);
 * ...
 * steps.complete(open, path + " · vault unlocked", null);
 * steps.activate(sign);
 * </pre>
 * Step indexes are 1-based, as the markers are numbered.
 */
public class StepperPanel extends JPanel {

    public enum State {TODO, ACTIVE, DONE}

    private static final int DOT = 28;

    private final List<Step> steps = new ArrayList<>();

    public StepperPanel() {
        super(new MigLayout("insets 0, gapx 14, gapy 0, hidemode 3, fillx, wrap 2", "[" + (DOT + 2) + "!,center][grow,fill]"));
        setOpaque(false);
    }

    /** Descriptions wrap at the width the content column actually has. */
    @Override
    public void doLayout() {
        int w = getWidth() - (DOT + 2) - 14;
        if (w >= 40) for (Step s : steps) s.description.setWrapWidth(w);
        super.doLayout();
    }

    /**
     * Appends a step. The first step added is active; later ones start as to-do.
     *
     * @param title       the step's heading
     * @param description one line under the heading, or null
     * @param body        the step's content, shown while the step is not done
     * @return the step's 1-based index
     */
    public int addStep(String title, String description, JComponent body) {
        Step step = new Step(steps.size() + 1, title, description, body);
        steps.add(step);
        add(step.dot, "aligny top, gaptop 1");
        add(step.header, "growx");
        add(step.rail, "growy, aligny top, gaptop 6, gapbottom 6");
        add(step.content, "growx, gapbottom 22");
        step.setState(steps.size() == 1 ? State.ACTIVE : State.TODO);
        relayoutRails();
        return step.index;
    }

    /** Makes a step the active one; done steps stay done, every other step becomes to-do. */
    public void activate(int index) {
        for (Step s : steps) {
            if (s.index == index) s.setState(State.ACTIVE);
            else if (s.state != State.DONE) s.setState(State.TODO);
        }
    }

    /**
     * Marks a step done and collapses its body to {@code summary}.
     *
     * @param onChange reopens the step when its Change button is pressed; null hides the button
     */
    public void complete(int index, String summary, Runnable onChange) {
        Step s = step(index);
        s.summary.setText(summary != null ? summary : "");
        s.onChange = onChange;
        s.change.setVisible(onChange != null);
        s.showSummary(true);
        s.setState(State.DONE);
    }

    /** Shows a done step's body again and makes it active. */
    public void reopen(int index) {
        Step s = step(index);
        s.showSummary(false);
        activate(index);
    }

    public State getState(int index) {
        return step(index).state;
    }

    public int getStepCount() {
        return steps.size();
    }

    public JComponent getBody(int index) {
        return step(index).body;
    }

    /** Enables or disables a step's body and header (a to-do step waiting on an earlier one). */
    public void setStepEnabled(int index, boolean enabled) {
        Step s = step(index);
        setTreeEnabled(s.body, enabled);
        s.title.setEnabled(enabled);
    }

    private Step step(int index) {
        if (index < 1 || index > steps.size())
            throw new IndexOutOfBoundsException("step " + index + " of " + steps.size());
        return steps.get(index - 1);
    }

    /** The last step draws no rail; the component stays in the grid so the cells keep their columns. */
    private void relayoutRails() {
        for (int i = 0; i < steps.size(); i++) {
            steps.get(i).rail.line = i < steps.size() - 1;
            steps.get(i).rail.repaint();
        }
    }

    private static void setTreeEnabled(JComponent root, boolean enabled) {
        root.setEnabled(enabled);
        for (java.awt.Component c : root.getComponents())
            if (c instanceof JComponent) setTreeEnabled((JComponent) c, enabled);
            else c.setEnabled(enabled);
    }

    private final class Step {
        final int index;
        final Dot dot;
        final JPanel header = new JPanel(new MigLayout("insets 0, gapy 0, wrap 1, fillx", "[grow,fill]"));
        final JLabel title;
        final WrapLabel description;
        final Rail rail = new Rail();
        // body and summary are siblings toggled by visibility (hidemode 3), not CardLayout cards:
        // a CardLayout keeps the tallest card's height, which left a collapsed step as tall as its form
        final JPanel content = new JPanel(new MigLayout("insets 0, wrap 1, hidemode 3, fillx", "[grow,fill]"));
        final JPanel bodyCard;
        final JPanel summaryCard;
        final JComponent body;
        final JLabel summary = new JLabel();
        final JButton change = new JButton("Change");
        State state = State.TODO;
        Runnable onChange;

        Step(int index, String titleText, String descriptionText, JComponent body) {
            this.index = index;
            this.body = body;
            dot = new Dot(index);

            title = new JLabel(titleText);
            title.setFont(UITokens.font(Font.BOLD, 2f));
            header.setOpaque(false);
            header.add(title);
            description = new WrapLabel(descriptionText != null ? descriptionText : "");
            description.setForeground(UITokens.muted());
            description.setVisible(descriptionText != null && !descriptionText.isEmpty());
            header.add(description, "growx, wmin 0");

            content.setOpaque(false);
            bodyCard = new JPanel(new MigLayout("insets 10 0 0 0, fillx", "[grow,fill]"));
            bodyCard.setOpaque(false);
            bodyCard.add(body, "growx");
            content.add(bodyCard, "growx");

            summaryCard = new JPanel(new MigLayout("insets 6 0 0 0, gapx 10", "[grow][]"));
            summaryCard.setOpaque(false);
            summary.setFont(UITokens.mono(-1f));
            summary.setForeground(UITokens.muted());
            summaryCard.add(summary, "growx, wmin 0");
            change.putClientProperty(FlatClientProperties.BUTTON_TYPE, FlatClientProperties.BUTTON_TYPE_TOOLBAR_BUTTON);
            change.addActionListener(e -> {
                if (onChange != null) onChange.run();
            });
            summaryCard.add(change);
            content.add(summaryCard, "growx");
            summaryCard.setVisible(false);
        }

        void showSummary(boolean done) {
            bodyCard.setVisible(!done);
            summaryCard.setVisible(done);
            content.revalidate();
            content.repaint();
        }

        void setState(State s) {
            state = s;
            dot.state = s;
            dot.repaint();
            title.setForeground(s == State.TODO ? UITokens.muted() : UITokens.text());
            description.setVisible(s != State.DONE && description.getPlainText().length() > 0);
            rail.repaint();
        }
    }

    /** The numbered circle: accent with a white number when active, a check when done, muted otherwise. */
    private static final class Dot extends JComponent {
        final int number;
        State state = State.TODO;

        Dot(int number) {
            this.number = number;
            Dimension d = new Dimension(DOT, DOT);
            setPreferredSize(d);
            setMinimumSize(d);
            setMaximumSize(d);
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                Color bg, fg;
                switch (state) {
                    case DONE:
                        bg = UITokens.okSoft();
                        fg = UITokens.ok();
                        break;
                    case ACTIVE:
                        bg = UITokens.accent();
                        fg = Color.WHITE;
                        break;
                    default:
                        bg = UITokens.neutralSoft();
                        fg = UITokens.muted();
                }
                g2.setColor(bg);
                g2.fillOval(0, 0, DOT, DOT);
                g2.setColor(fg);
                if (state == State.DONE) {
                    g2.setStroke(new BasicStroke(2.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                    int x = DOT / 2, y = DOT / 2;
                    g2.drawLine(x - 6, y, x - 2, y + 4);
                    g2.drawLine(x - 2, y + 4, x + 6, y - 4);
                } else {
                    g2.setFont(UITokens.font(Font.BOLD, -0.5f));
                    String s = Integer.toString(number);
                    FontMetrics fm = g2.getFontMetrics();
                    int tx = (DOT - fm.stringWidth(s)) / 2;
                    int ty = (DOT - fm.getHeight()) / 2 + fm.getAscent();
                    g2.drawString(s, tx, ty);
                }
            } finally {
                g2.dispose();
            }
        }
    }

    /** The 2 px line between two markers; drawn only when {@link #line} is set (not after the last step). */
    private static final class Rail extends JComponent {
        boolean line = true;

        Rail() {
            setPreferredSize(new Dimension(2, 16));
            setMinimumSize(new Dimension(2, 8));
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            if (!line) return;
            g.setColor(UITokens.border());
            g.fillRect(0, 0, getWidth(), getHeight());
        }
    }
}
