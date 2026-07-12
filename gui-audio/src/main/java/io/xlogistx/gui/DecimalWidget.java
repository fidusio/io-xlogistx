package io.xlogistx.gui;

import javax.swing.*;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.*;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Locale;

/**
 * Text-field editor for decimal (floating point) values. A {@link DocumentFilter}
 * rejects any edit that would not parse as a double, and the parsed value is cached
 * and exposed via {@link #getValue()}. Displayed values are formatted with up to
 * four fraction digits. Used by {@link MetaToWidget} to edit NVFloat/NVDouble entries.
 */
// DecimalWidget using JTextField with decimal validation
public class DecimalWidget extends JTextField {
    // US symbols so the '.' separator matches Double.parseDouble in the document filter,
    // otherwise setValue's own text would be rejected on comma-decimal locales
    private static final DecimalFormat DECIMAL_FORMAT = new DecimalFormat("#.####", DecimalFormatSymbols.getInstance(Locale.US));
    private double value;

    /**
     * Factory used by {@link MetaToWidget}; returns a widget initialized to 0.0.
     *
     * @param param factory parameters (unused)
     * @return a new DecimalWidget
     */
    protected static DecimalWidget create(Object... param) {
        return new DecimalWidget(null, 0.0);
    }

    /** Creates a decimal field initialized to 0.0 with no tooltip label. */
    public DecimalWidget() {
        this(null, 0.0);
    }

    /**
     * Creates a right-aligned decimal field.
     *
     * @param label        tooltip text, may be null
     * @param initialValue initial value to display
     */
    public DecimalWidget(String label, double initialValue) {
        super(10);
        setValue(initialValue);
        setHorizontalAlignment(JTextField.RIGHT);
        setFont(new Font("Arial", Font.PLAIN, 12));
        setToolTipText(label);

        // Add document filter for decimal validation; insertString and remove are routed
        // through replace so deletions also revalidate and refresh the cached value
        ((AbstractDocument) getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void insertString(DocumentFilter.FilterBypass fb, int offset, String text, AttributeSet attrs) throws BadLocationException {
                replace(fb, offset, 0, text, attrs);
            }

            @Override
            public void remove(DocumentFilter.FilterBypass fb, int offset, int length) throws BadLocationException {
                replace(fb, offset, length, "", null);
            }

            @Override
            public void replace(DocumentFilter.FilterBypass fb, int offset, int length, String text, AttributeSet attrs) throws BadLocationException {
                if (text == null)
                    text = "";
                String currentText = fb.getDocument().getText(0, fb.getDocument().getLength());
                String newText = currentText.substring(0, offset) + text + currentText.substring(offset + length);

                if (isValidDecimal(newText)) {
                    super.replace(fb, offset, length, text, attrs);
                    try {
                        value = Double.parseDouble(newText);
                    } catch (NumberFormatException e) {
                        value = 0.0;
                    }
                }
            }
        });
    }

    private boolean isValidDecimal(String text) {
        if (text.isEmpty() || text.equals("-")) return true;
        try {
            Double.parseDouble(text);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Returns the last successfully parsed value.
     *
     * @return the current decimal value
     */
    public double getValue() {
        return value;
    }

    /**
     * Sets the value and updates the displayed text (formatted to at most four
     * fraction digits).
     *
     * @param value value to set
     */
    public void setValue(double value) {
        this.value = value;
        setText(DECIMAL_FORMAT.format(value));
    }
}

