package io.xlogistx.gui;

import javax.swing.*;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.*;

// LongWidget using JTextField with long integer validation
public class LongWidget extends JTextField {
    private long value;

    protected static LongWidget create(Object... param) {
        return new LongWidget(null, 0);
    }

    public LongWidget() {
        this(null, 0);
    }

    public LongWidget(String label, long initialValue) {
        super(10);
        setValue(initialValue);
        setHorizontalAlignment(JTextField.RIGHT);
        setFont(new Font("Arial", Font.PLAIN, 12));
        setToolTipText(label);

        // Add document filter for long integer validation
        ((AbstractDocument) getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs) throws BadLocationException {
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

    public long getValue() {
        return value;
    }

    public void setValue(long value) {
        this.value = value;
        setText(String.valueOf(value));
    }
}
