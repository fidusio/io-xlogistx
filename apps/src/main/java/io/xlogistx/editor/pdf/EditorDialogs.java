package io.xlogistx.editor.pdf;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;

/**
 * The small modal dialogs the editor uses: text entry, page selection with a
 * position, and annotation properties. All return null when cancelled.
 */
public final class EditorDialogs {

    private EditorDialogs() {
    }

    /**
     * Asks for a text.
     *
     * @param parent    the dialog parent
     * @param title     the dialog title
     * @param initial   the initial text, may be null
     * @param multiline true for a text area, false for a single line
     * @return the text, null when cancelled
     */
    public static String askText(Component parent, String title, String initial, boolean multiline) {
        JTextComponent tc;
        JComponent shown;
        if (multiline) {
            JTextArea area = new JTextArea(initial == null ? "" : initial, 6, 36);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            tc = area;
            shown = new JScrollPane(area);
        } else {
            JTextField f = new JTextField(initial == null ? "" : initial, 36);
            tc = f;
            shown = f;
        }
        JPanel form = new JPanel(new BorderLayout(0, 4));
        form.add(new JLabel("Text:"), BorderLayout.NORTH);
        form.add(shown, BorderLayout.CENTER);
        int r = JOptionPane.showConfirmDialog(parent, form, title, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        return r == JOptionPane.OK_OPTION ? tc.getText() : null;
    }

    /** Result of {@link #askTextAligned}: the replacement, where it sits in the old text's room and how it is written. */
    public static final class AlignedText {
        public final String text;
        public final TextEditor.Alignment alignment;
        /** Font, size and colour of the replacement; {@link TextEditor.Format#SAME} keeps those of the old text. */
        public final TextEditor.Format format;

        AlignedText(String text, TextEditor.Alignment alignment) {
            this(text, alignment, TextEditor.Format.SAME);
        }

        AlignedText(String text, TextEditor.Alignment alignment, TextEditor.Format format) {
            this.text = text;
            this.alignment = alignment;
            this.format = format == null ? TextEditor.Format.SAME : format;
        }
    }

    /** {@link #askTextAligned(Component, String, String, TextEditor.Alignment, float, Color, int)} showing 12 pt plain black as the current look. */
    public static AlignedText askTextAligned(Component parent, String title, String initial, TextEditor.Alignment initialAlignment) {
        return askTextAligned(parent, title, initial, initialAlignment, 12f, Color.BLACK, Font.PLAIN);
    }

    /**
     * Asks for a single-line replacement text and its alignment inside the room
     * the old text took (nothing reflows: left keeps the start, right the end).
     *
     * The font, face, size and colour of the old text are kept unless changed:
     * the font list starts with "keep", the Bold / Italic boxes, the size
     * spinner and the colour button show the current values; Underline and
     * Strikethrough draw a line under / through the replacement, Highlight a
     * colour band behind it.
     *
     * @param parent           the dialog parent
     * @param title            the dialog title
     * @param initial          the current text
     * @param initialAlignment the pre-selected alignment
     * @param currentSize      the rendered size of the old text in points
     * @param currentColor     the colour of the old text (null = unknown, shown as black)
     * @param currentStyle     the {@link Font} style bits of the old text's face
     * @return the text, alignment and format, null when cancelled
     */
    public static AlignedText askTextAligned(Component parent, String title, String initial, TextEditor.Alignment initialAlignment,
                                            float currentSize, Color currentColor, int currentStyle) {
        float size0 = currentSize > 0 ? Math.round(currentSize * 10f) / 10f : 12f;
        Color color0 = currentColor == null ? Color.BLACK : currentColor;
        JTextField field = new JTextField(initial == null ? "" : initial, 36);
        JRadioButton left = new JRadioButton("Left (keep the start)");
        JRadioButton center = new JRadioButton("Centre");
        JRadioButton right = new JRadioButton("Right (keep the end)");
        ButtonGroup g = new ButtonGroup();
        g.add(left);
        g.add(center);
        g.add(right);
        TextEditor.Alignment a = initialAlignment == null ? TextEditor.Alignment.LEFT : initialAlignment;
        (a == TextEditor.Alignment.RIGHT ? right : a == TextEditor.Alignment.CENTER ? center : left).setSelected(true);
        JPanel form = new JPanel();
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        JLabel label = new JLabel("Text (no reflow; the font, size and colour below stay unless changed):");
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        field.setAlignmentX(Component.LEFT_ALIGNMENT);
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        row.add(new JLabel("Align:"));
        row.add(left);
        row.add(center);
        row.add(right);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        // font, size and colour: kept unless changed
        JComboBox<String> family = fontCombo(null);
        family.insertItemAt(KEEP_FONT, 0);
        family.setSelectedIndex(0);
        JCheckBox bold = new JCheckBox("Bold", (currentStyle & Font.BOLD) != 0);
        JCheckBox italic = new JCheckBox("Italic", (currentStyle & Font.ITALIC) != 0);
        JCheckBox underline = new JCheckBox("Underline");
        JCheckBox strike = new JCheckBox("Strikethrough");
        bold.setToolTipText("Another face of the same family (it must be installed), or of the font chosen here");
        italic.setToolTipText(bold.getToolTipText());
        JSpinner size = new JSpinner(new SpinnerNumberModel((double) size0, 1.0, 400.0, 0.5));
        Color[] color = {color0};
        JButton colorButton = colorButton("Font colour", color, false);
        Color[] highlight = {null};
        JButton highlightButton = colorButton("Text highlight", highlight, true);
        JPanel fontRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        fontRow.add(new JLabel("Font:"));
        fontRow.add(family);
        fontRow.add(bold);
        fontRow.add(italic);
        fontRow.add(underline);
        fontRow.add(strike);
        fontRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        JPanel lookRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        lookRow.add(new JLabel("Size (pt):"));
        lookRow.add(size);
        lookRow.add(new JLabel("Font colour:"));
        lookRow.add(colorButton);
        lookRow.add(new JLabel("Highlight:"));
        lookRow.add(highlightButton);
        lookRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.add(label);
        form.add(field);
        form.add(Box.createVerticalStrut(6));
        form.add(row);
        form.add(Box.createVerticalStrut(6));
        form.add(fontRow);
        form.add(Box.createVerticalStrut(4));
        form.add(lookRow);
        int r = JOptionPane.showConfirmDialog(parent, form, title, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (r != JOptionPane.OK_OPTION)
            return null;
        String chosenFamily = family.getSelectedIndex() > 0 ? (String) family.getSelectedItem() : null;
        int style = (bold.isSelected() ? Font.BOLD : 0) | (italic.isSelected() ? Font.ITALIC : 0);
        float chosenSize = ((Number) size.getValue()).floatValue();
        if (Math.abs(chosenSize - size0) < 0.05f)
            chosenSize = 0f; // kept
        Color chosenColor = color[0] == null || color[0].equals(color0) ? null : color[0];
        TextEditor.Format format = new TextEditor.Format(chosenFamily, style, chosenSize, chosenColor, underline.isSelected(), strike.isSelected(), highlight[0]);
        return new AlignedText(field.getText(), right.isSelected() ? TextEditor.Alignment.RIGHT
                : center.isSelected() ? TextEditor.Alignment.CENTER : TextEditor.Alignment.LEFT, format);
    }

    /** The first entry of the edit-text font list: keep the font of the old text. */
    public static final String KEEP_FONT = "(keep the current font)";

    /**
     * A font family chooser listing {@link EditorFonts#families()}, each
     * family shown in its own face.
     *
     * @param selected the family to pre-select, added when not listed; null for the first entry
     */
    public static JComboBox<String> fontCombo(String selected) {
        JComboBox<String> combo = new JComboBox<>(EditorFonts.families().toArray(new String[0]));
        combo.setMaximumRowCount(24);
        combo.setPrototypeDisplayValue("Times New Roman Bold");
        combo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                Component c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (index >= 0 && value instanceof String && !EditorFonts.isBundled((String) value) && !KEEP_FONT.equals(value))
                    try {
                        c.setFont(new Font((String) value, Font.PLAIN, c.getFont().getSize()));
                    } catch (RuntimeException ignore) {
                        // keep the list font
                    }
                return c;
            }
        });
        if (selected != null)
            selectFamily(combo, selected);
        return combo;
    }

    /** Selects a family in a {@link #fontCombo}, adding it when it is not listed (a font the document names but the system lacks). */
    public static void selectFamily(JComboBox<String> combo, String family) {
        String f = EditorFonts.familyOrDefault(family);
        for (int i = 0; i < combo.getItemCount(); i++)
            if (f.equalsIgnoreCase(combo.getItemAt(i))) {
                combo.setSelectedIndex(i);
                return;
            }
        combo.addItem(f);
        combo.setSelectedItem(f);
    }

    /** The target position of a move: the zero-based index the block lands in front of, computed from the choice. */
    public static final class PositionChoice {
        /** 0 = beginning, pageCount = end, n = after page n (one-based n). */
        public final int targetIndex;

        PositionChoice(int targetIndex) {
            this.targetIndex = targetIndex;
        }
    }

    /**
     * Asks for a one-based page selection ({@code current}, pages, ranges, lists)
     * and, optionally, a position (beginning / end / after page n).
     *
     * @param parent       the dialog parent
     * @param title        the dialog title
     * @param prompt       the label over the selection field
     * @param currentPage  zero-based current page, -1 for none (pre-fills the field)
     * @param pageCount    the number of pages
     * @param withPosition whether to ask for a position too
     * @return {@code {pages..., -1, targetIndex}}: the zero-based pages, a -1 separator and the
     *         target index (only with a position, else the array ends at the separator); null when cancelled
     */
    public static int[] askPages(Component parent, String title, String prompt, int currentPage, int pageCount, boolean withPosition) {
        JTextField field = new JTextField(currentPage >= 0 ? String.valueOf(currentPage + 1) : "", 16);
        JPanel form = new JPanel();
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        JLabel label = new JLabel(prompt);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        field.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel hint = new JLabel("current, 3, 5-8 or a comma separated list (1-" + pageCount + ")");
        hint.setFont(hint.getFont().deriveFont(hint.getFont().getSize2D() - 1f));
        hint.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.add(label);
        form.add(field);
        form.add(hint);

        JRadioButton begin = new JRadioButton("At the beginning");
        JRadioButton end = new JRadioButton("At the end", true);
        JRadioButton after = new JRadioButton("After page");
        JSpinner spinner = new JSpinner(new SpinnerNumberModel(Math.max(1, currentPage + 1), 1, Math.max(1, pageCount), 1));
        if (withPosition) {
            ButtonGroup g = new ButtonGroup();
            g.add(begin);
            g.add(end);
            g.add(after);
            spinner.addChangeListener(e -> after.setSelected(true));
            JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            row.add(after);
            row.add(spinner);
            row.add(new JLabel("of " + pageCount));
            row.setAlignmentX(Component.LEFT_ALIGNMENT);
            begin.setAlignmentX(Component.LEFT_ALIGNMENT);
            end.setAlignmentX(Component.LEFT_ALIGNMENT);
            form.add(Box.createVerticalStrut(8));
            JLabel to = new JLabel("Move to:");
            to.setAlignmentX(Component.LEFT_ALIGNMENT);
            form.add(to);
            form.add(begin);
            form.add(end);
            form.add(row);
        }
        while (true) {
            int r = JOptionPane.showConfirmDialog(parent, form, title, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (r != JOptionPane.OK_OPTION)
                return null;
            try {
                int[] pages = io.xlogistx.gui.PDFViewerPanel.parsePageSelection(field.getText(), currentPage, pageCount);
                int target = begin.isSelected() ? 0 : end.isSelected() ? pageCount : ((Number) spinner.getValue()).intValue();
                int[] ret = new int[pages.length + (withPosition ? 2 : 1)];
                System.arraycopy(pages, 0, ret, 0, pages.length);
                ret[pages.length] = -1;
                if (withPosition)
                    ret[pages.length + 1] = target;
                return ret;
            } catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(parent, e.getMessage(), title, JOptionPane.WARNING_MESSAGE);
            }
        }
    }

    /** @return the pages part of an {@link #askPages} result */
    public static int[] pagesOf(int[] result) {
        int n = 0;
        while (n < result.length && result[n] >= 0)
            n++;
        int[] pages = new int[n];
        System.arraycopy(result, 0, pages, 0, n);
        return pages;
    }

    /** @return the target index of an {@link #askPages} result asked with a position */
    public static int targetOf(int[] result) {
        return result[result.length - 1];
    }

    /**
     * Edits an {@link AnnotationStyle}.
     *
     * @param parent   the dialog parent
     * @param style    the current style
     * @param withFill whether the fill colour applies
     * @param withFont whether the font (family, face, size) applies
     * @return the new style, null when cancelled
     */
    public static AnnotationStyle askStyle(Component parent, AnnotationStyle style, boolean withFill, boolean withFont) {
        Color[] stroke = {style.getStrokeColor()};
        Color[] fill = {style.getFillColor()};
        JButton strokeButton = colorButton(withFont ? "Font colour" : "Stroke colour", stroke, false);
        JButton fillButton = colorButton("Fill / background", fill, true);
        JSlider opacity = new JSlider(0, 100, Math.round(style.getOpacity() * 100));
        opacity.setMajorTickSpacing(25);
        opacity.setPaintTicks(true);
        opacity.setPaintLabels(true);
        JSpinner width = new JSpinner(new SpinnerNumberModel((double) style.getStrokeWidth(), 0.0, 50.0, 0.5));
        JSpinner size = new JSpinner(new SpinnerNumberModel((double) style.getFontSize(), 4.0, 144.0, 1.0));
        JComboBox<String> family = fontCombo(style.getFontFamily());
        JCheckBox bold = new JCheckBox("Bold", style.isBold());
        JCheckBox italic = new JCheckBox("Italic", style.isItalic());
        JCheckBox underline = new JCheckBox("Underline", style.isUnderline());
        JCheckBox strike = new JCheckBox("Strikethrough", style.isStrikethrough());
        Color[] highlight = {style.getHighlightColor()};
        JButton highlightButton = colorButton("Text highlight", highlight, true);
        JRadioButton alignLeft = new JRadioButton("Left", style.getAlignment() == TextEditor.Alignment.LEFT);
        JRadioButton alignCenter = new JRadioButton("Centre", style.getAlignment() == TextEditor.Alignment.CENTER);
        JRadioButton alignRight = new JRadioButton("Right", style.getAlignment() == TextEditor.Alignment.RIGHT);
        ButtonGroup alignGroup = new ButtonGroup();
        alignGroup.add(alignLeft);
        alignGroup.add(alignCenter);
        alignGroup.add(alignRight);
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(3, 4, 3, 4);
        gc.anchor = GridBagConstraints.WEST;
        gc.fill = GridBagConstraints.HORIZONTAL;
        int row = 0;
        row = addRow(form, gc, row, withFont ? "Font colour:" : "Colour:", strokeButton);
        if (withFill)
            row = addRow(form, gc, row, "Fill:", fillButton);
        row = addRow(form, gc, row, "Opacity:", opacity);
        row = addRow(form, gc, row, "Width (pt):", width);
        if (withFont) {
            row = addRow(form, gc, row, "Font:", family);
            JPanel face = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            face.add(bold);
            face.add(italic);
            face.add(underline);
            face.add(strike);
            row = addRow(form, gc, row, "Face:", face);
            row = addRow(form, gc, row, "Highlight:", highlightButton);
            JPanel align = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            align.add(alignLeft);
            align.add(alignCenter);
            align.add(alignRight);
            row = addRow(form, gc, row, "Align:", align);
            addRow(form, gc, row, "Font size (pt):", size);
        }
        int r = JOptionPane.showConfirmDialog(parent, form, "Annotation properties", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (r != JOptionPane.OK_OPTION)
            return null;
        int fontStyle = withFont ? (bold.isSelected() ? Font.BOLD : 0) | (italic.isSelected() ? Font.ITALIC : 0) : style.getFontStyle();
        return new AnnotationStyle(stroke[0], withFill ? fill[0] : style.getFillColor(), opacity.getValue() / 100f,
                ((Number) width.getValue()).floatValue(), ((Number) size.getValue()).floatValue(),
                withFont ? (String) family.getSelectedItem() : style.getFontFamily(), fontStyle,
                withFont ? underline.isSelected() : style.isUnderline(), withFont ? strike.isSelected() : style.isStrikethrough(),
                withFont ? highlight[0] : style.getHighlightColor(),
                !withFont ? style.getAlignment() : alignRight.isSelected() ? TextEditor.Alignment.RIGHT
                        : alignCenter.isSelected() ? TextEditor.Alignment.CENTER : TextEditor.Alignment.LEFT, style.getAuthor());
    }

    /**
     * Edits the opacity of an image stamp (the only style it has).
     *
     * @return the new style, null when cancelled
     */
    public static AnnotationStyle askImageStyle(Component parent, AnnotationStyle style) {
        JSlider opacity = new JSlider(0, 100, Math.round(style.getOpacity() * 100));
        opacity.setMajorTickSpacing(25);
        opacity.setPaintTicks(true);
        opacity.setPaintLabels(true);
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(3, 4, 3, 4);
        gc.anchor = GridBagConstraints.WEST;
        gc.fill = GridBagConstraints.HORIZONTAL;
        addRow(form, gc, 0, "Opacity:", opacity);
        int r = JOptionPane.showConfirmDialog(parent, form, "Image properties", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (r != JOptionPane.OK_OPTION)
            return null;
        return style.withOpacity(opacity.getValue() / 100f);
    }

    private static int addRow(JPanel form, GridBagConstraints gc, int row, String label, JComponent c) {
        gc.gridx = 0;
        gc.gridy = row;
        gc.weightx = 0;
        form.add(new JLabel(label), gc);
        gc.gridx = 1;
        gc.weightx = 1;
        form.add(c, gc);
        return row + 1;
    }

    private static JButton colorButton(String title, Color[] holder, boolean allowNone) {
        JButton b = new JButton();
        Runnable paint = () -> {
            Color c = holder[0];
            b.setText(c == null ? "none" : String.format("#%02X%02X%02X", c.getRed(), c.getGreen(), c.getBlue()));
            b.setIcon(new Icon() {
                @Override
                public void paintIcon(Component comp, Graphics g, int x, int y) {
                    if (holder[0] == null) {
                        g.setColor(Color.GRAY);
                        g.drawRect(x, y, 15, 15);
                        g.drawLine(x, y + 15, x + 15, y);
                    } else {
                        g.setColor(holder[0]);
                        g.fillRect(x, y, 16, 16);
                        g.setColor(Color.DARK_GRAY);
                        g.drawRect(x, y, 15, 15);
                    }
                }

                @Override
                public int getIconWidth() {
                    return 16;
                }

                @Override
                public int getIconHeight() {
                    return 16;
                }
            });
        };
        paint.run();
        b.addActionListener(e -> {
            Color chosen = JColorChooser.showDialog(b, title, holder[0] != null ? holder[0] : allowNone ? AnnotationStyle.MARKER_YELLOW : Color.WHITE);
            if (chosen != null) {
                holder[0] = chosen;
                paint.run();
            } else if (allowNone && holder[0] != null
                    && JOptionPane.showConfirmDialog(b, "Remove the fill?", title, JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                holder[0] = null;
                paint.run();
            }
        });
        return b;
    }
}
