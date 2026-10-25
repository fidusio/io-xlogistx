package io.xlogistx.gui;

import javax.swing.BorderFactory;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.JTableHeader;
import java.awt.Dimension;
import java.awt.Font;

/**
 * The house table look, applied to any {@link JTable}: taller rows, no grid, a quiet bold header
 * on the recessed surface, accent-soft selection, sorting on header click. Static helpers only.
 */
public final class Tables {

    private Tables() {
    }

    /** Applies the look and returns the same table, for chaining. */
    public static JTable style(JTable table) {
        table.setRowHeight(32);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 0));
        table.setFillsViewportHeight(true);
        table.setAutoCreateRowSorter(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setSelectionBackground(UITokens.accentSoft());
        table.setSelectionForeground(UITokens.accentText());
        table.setFont(UITokens.font(Font.PLAIN, 0f));
        table.putClientProperty("JTable.alternateRowColor", null);

        JTableHeader header = table.getTableHeader();
        header.setFont(UITokens.font(Font.BOLD, -1.5f));
        header.setForeground(UITokens.muted());
        header.setBackground(UITokens.surfaceAlt());
        header.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UITokens.border()));
        header.setReorderingAllowed(false);
        header.setPreferredSize(new Dimension(header.getPreferredSize().width, 34));
        return table;
    }

    /** Sets a column's preferred width (and min for the first {@code fixed} pixels) by index. */
    public static void width(JTable table, int column, int preferred) {
        table.getColumnModel().getColumn(column).setPreferredWidth(preferred);
    }
}
