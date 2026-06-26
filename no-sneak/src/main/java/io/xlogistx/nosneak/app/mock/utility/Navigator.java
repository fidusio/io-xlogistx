package io.xlogistx.nosneak.app.mock.utility;

import javax.swing.*;
import java.awt.*;

public class Navigator {
    public enum Screen {LOGIN, REGISTER, MAIN, SCAN, SUBJECT}

    private final CardLayout cards;
    private final JPanel content;

    public Navigator(CardLayout cards, JPanel content) {
        this.cards = cards;
        this.content = content;
    }

    public void show(Screen s) {
        cards.show(content, s.name());
    }
}
