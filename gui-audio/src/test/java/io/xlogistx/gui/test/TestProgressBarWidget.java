package io.xlogistx.gui.test;

import io.xlogistx.gui.ProgressBarWidget;
import org.zoxweb.shared.util.PercentConverter;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class TestProgressBarWidget {
    public static void main(String[] args) {
        ProgressBarWidget progressBar = new ProgressBarWidget("test", new FlowLayout(FlowLayout.LEFT), new PercentConverter(0, 100));

        // Create a JFrame (invisible, used as parent for JFileChooser)
        JFrame frame = new JFrame();
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);


        frame.add(progressBar);
        frame.setSize(150,75);
        frame.setLocationRelativeTo(null);
        SwingUtilities.invokeLater(()-> frame.setVisible(true));


        // Create a timer to update the progress
        new Timer(100, new ActionListener() {
            int progress = (int)progressBar.currentValue();
            @Override
            public void actionPerformed(ActionEvent e) {
                progressBar.currentValue(progress++);

                if(progress > progressBar.getPercentConverter().iRange().getEnd())
                    progress = progressBar.getPercentConverter().iRange().getStart();

            }
        }).start();
    }
}
