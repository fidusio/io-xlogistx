package io.xlogistx.gui;

import org.junit.jupiter.api.Test;

import javax.swing.JTextField;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** {@link GUIUtil#limitLength}: typing, pasting and setText never leave more than the limit. */
class GUIUtilLimitLengthTest {

    @Test
    void theTextNeverExceedsTheLimit() throws Exception {
        JTextField f = GUIUtil.limitLength(new JTextField(), 5);
        f.setText("abc");
        assertEquals("abc", f.getText());
        f.getDocument().insertString(3, "defgh", null);   // a paste: cut to what fits
        assertEquals("abcde", f.getText());
        f.getDocument().insertString(0, "x", null);       // full: typing does nothing
        assertEquals("abcde", f.getText());
        f.setText("0123456789");                          // setText is cut too
        assertEquals("01234", f.getText());
        f.select(0, 2);
        f.replaceSelection("XYZ");                        // replacing 2 leaves room for 2
        assertEquals("XY234", f.getText());
        f.setText("");
        assertEquals("", f.getText());
    }
}
