package io.xlogistx.gui;

import org.zoxweb.shared.data.Range;
import org.zoxweb.shared.util.PercentConverter;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;

public class ProgressBarWidget extends JPanel
{

    public static final int DEFAULT_RANGE_MAX = 100;

    private final JProgressBar progressBar;

    private long currentValue;

    private PercentConverter percentConverter;
    private Range<Integer> range;
    private JLabel valueLabel = new JLabel();

    public ProgressBarWidget(String name,
                             LayoutManager layoutManager)
    {
        this(name, layoutManager, new PercentConverter(0, DEFAULT_RANGE_MAX));
    }


    public ProgressBarWidget(String name,
                             LayoutManager layoutManager,
                             PercentConverter percentConverter)
    {

        setPercentConverter(percentConverter);
        // Create a JProgressBar
        progressBar = new JProgressBar(0, DEFAULT_RANGE_MAX);
        progressBar.setStringPainted(true);

        // Show percentage string on the bar
        // Initial value
        // Create a panel to hold the progress bar\
        setLayout(layoutManager);
        add(new JLabel(name));
        add(progressBar, BorderLayout.CENTER);
        add(valueLabel);
        setPercentConverter(percentConverter);
        currentValue(percentConverter.iRange().getStart());




    }

    public synchronized ProgressBarWidget currentValue(long progress)
    {

        if(progress < range.getStart() || progress > range.getEnd())
            throw new IllegalArgumentException("Invalid progress");
        currentValue = progress;
        SwingUtilities.invokeLater(()->updateProgress());
        return this;
    }

    public synchronized ProgressBarWidget setPercentConverter(PercentConverter percentValue)
    {
        SUS.checkIfNulls("PercentValue can't be null");
        this.percentConverter = percentValue;
        range = percentValue.iRange();
        return this;
    }
    public PercentConverter getPercentConverter()
    {
        return percentConverter;
    }

    public int currentPercent()
    {
        return percentConverter.iPercent(currentValue);
    }

    public long currentValue()
    {
        return currentValue;
    }

    private void updateProgress()
    {
        int percent = percentConverter.iPercent(currentValue);
        progressBar.setValue(percent);

        // Calculate a color interpolating from RED (0%) to GREEN (100%)
        // progressValue is in [0..100], so t = progressValue / 100.0
        float t = percent / 100.0f;

        // Start color (RED) = (255, 0, 0)
        // End color (GREEN) = (0, 255, 0)
        int startR = 255, startG = 0, startB = 128;
        int endR = 0, endG = 255, endB = 0;

        int r = (int) (startR + (endR - startR) * t);
        int g = (int) (startG + (endG - startG) * t);
        int b = (int) (startB + (endB - startB) * t);

        Color interpolatedColor = GUIUtil.colorToRation(t);
        progressBar.setForeground(interpolatedColor);
        valueLabel.setText(""+currentValue);
    }

}
