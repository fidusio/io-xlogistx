package io.xlogistx.gui;

import javax.swing.*;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.*;
import java.text.DecimalFormat;

// DecimalWidget using JTextField with decimal validation
public class DecimalWidget extends JTextField {
    private static final DecimalFormat DECIMAL_FORMAT = new DecimalFormat("#.####");
    private double value;

    protected static DecimalWidget create(Object... param) {
        return new DecimalWidget(null, 0.0);
    }

    public DecimalWidget() {
        this(null, 0.0);
    }

    public DecimalWidget(String label, double initialValue) {
        super(10);
        setValue(initialValue);
        setHorizontalAlignment(JTextField.RIGHT);
        setFont(new Font("Arial", Font.PLAIN, 12));
        setToolTipText(label);

        // Add document filter for decimal validation
        ((AbstractDocument) getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void replace(DocumentFilter.FilterBypass fb, int offset, int length, String text, AttributeSet attrs) throws BadLocationException {
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

    public double getValue() {
        return value;
    }

    public void setValue(double value) {
        this.value = value;
        setText(DECIMAL_FORMAT.format(value));
    }
}

