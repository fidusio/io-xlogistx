package io.xlogistx.gui;

import javax.swing.*;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.*;

/**
 * Text-field editor for integer values. A {@link DocumentFilter} rejects any edit
 * that would not parse as a long, and the parsed value is cached and exposed via
 * {@link #getValue()}. Used by {@link MetaToWidget} to edit NVInt/NVLong entries.
 */
// LongWidget using JTextField with long integer validation
public class LongWidget extends JTextField {
    private long value;

    /**
     * Factory used by {@link MetaToWidget}; returns a widget initialized to 0.
     *
     * @param param factory parameters (unused)
     * @return a new LongWidget
     */
    protected static LongWidget create(Object... param) {
        return new LongWidget(null, 0);
    }

    /** Creates a long field initialized to 0 with no tooltip label. */
    public LongWidget() {
        this(null, 0);
    }

    /**
     * Creates a right-aligned long integer field.
     *
     * @param label        tooltip text, may be null
     * @param initialValue initial value to display
     */
    public LongWidget(String label, long initialValue) {
        super(10);
        setValue(initialValue);
        setHorizontalAlignment(JTextField.RIGHT);
        setFont(new Font("Arial", Font.PLAIN, 12));
        setToolTipText(label);

        // Add document filter for long integer validation; insertString and remove are
        // routed through replace so deletions also revalidate and refresh the cached value
        ((AbstractDocument) getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void insertString(FilterBypass fb, int offset, String text, AttributeSet attrs) throws BadLocationException {
                replace(fb, offset, 0, text, attrs);
            }

            @Override
            public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
                replace(fb, offset, length, "", null);
            }

            @Override
            public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs) throws BadLocationException {
                if (text == null)
                    text = "";
                String currentText = fb.getDocument().getText(0, fb.getDocument().getLength());
                String newText = currentText.substring(0, offset) + text + currentText.substring(offset + length);

                if (isValidLong(newText)) {
                    super.replace(fb, offset, length, text, attrs);
                    try {
                        value = Long.parseLong(newText);
                    } catch (NumberFormatException e) {
                        value = 0L;
                    }
                }
            }
        });
    }

    private boolean isValidLong(String text) {
        if (text.isEmpty() || text.equals("-")) return true;
        try {
            Long.parseLong(text);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Returns the last successfully parsed value.
     *
     * @return the current long value
     */
    public long getValue() {
        return value;
    }

    /**
     * Sets the value and updates the displayed text.
     *
     * @param value value to set
     */
    public void setValue(long value) {
        this.value = value;
        setText(String.valueOf(value));
    }
}
