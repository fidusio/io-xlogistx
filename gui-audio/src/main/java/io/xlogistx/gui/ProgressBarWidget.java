package io.xlogistx.gui;

import org.zoxweb.shared.data.Range;
import org.zoxweb.shared.util.PercentConverter;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;

/**
 * Panel combining a name label, a percentage progress bar and a raw-value label.
 * Raw values are converted to a 0-100 percentage through a {@link PercentConverter},
 * and the bar's foreground color is interpolated along the default gradient
 * (red at 0% to green at 100%) via {@link GUIUtil#colorToRatio(float)}.
 * <p>
 * {@link #currentValue(long)} is safe to call from any thread; the visual update is
 * dispatched to the EDT.
 */
public class ProgressBarWidget extends JPanel
{

    /** Upper bound of the progress bar's internal percentage scale and of the default converter range. */
    public static final int DEFAULT_RANGE_MAX = 100;

    private final JProgressBar progressBar;

    private long currentValue;

    private PercentConverter percentConverter;
    private Range<Integer> range;
    private JLabel valueLabel = new JLabel();

    /**
     * Creates a progress bar widget with a default 0-100 value range.
     *
     * @param name          label displayed next to the bar
     * @param layoutManager layout of this panel
     */
    public ProgressBarWidget(String name,
                             LayoutManager layoutManager)
    {
        this(name, layoutManager, new PercentConverter(0, DEFAULT_RANGE_MAX));
    }


    /**
     * Creates a progress bar widget.
     *
     * @param name             label displayed next to the bar
     * @param layoutManager    layout of this panel
     * @param percentConverter converter mapping raw values to a 0-100 percentage;
     *                         must not be null
     */
    public ProgressBarWidget(String name,
                             LayoutManager layoutManager,
                             PercentConverter percentConverter)
    {

        setPercentConverter(percentConverter);
        // Create a JProgressBar
        progressBar = new JProgressBar(0, DEFAULT_RANGE_MAX);
        progressBar.setStringPainted(true);

        setLayout(layoutManager);
        add(new JLabel(name));
        add(progressBar);
        add(valueLabel);
        currentValue(percentConverter.iRange().getStart());
    }

    /**
     * Sets the current raw value and schedules a visual refresh on the EDT.
     *
     * @param progress raw value; must lie within the converter's range
     * @return this widget for chaining
     * @throws IllegalArgumentException if the value is outside the converter's range
     */
    public synchronized ProgressBarWidget currentValue(long progress)
    {

        if(progress < range.getStart() || progress > range.getEnd())
            throw new IllegalArgumentException("Invalid progress");
        currentValue = progress;
        SwingUtilities.invokeLater(()->updateProgress());
        return this;
    }

    /**
     * Replaces the value-to-percentage converter and adopts its range.
     *
     * @param percentValue new converter; must not be null
     * @return this widget for chaining
     * @throws NullPointerException if the converter is null
     */
    public synchronized ProgressBarWidget setPercentConverter(PercentConverter percentValue)
    {
        SUS.checkIfNulls("PercentValue can't be null", percentValue);
        this.percentConverter = percentValue;
        range = percentValue.iRange();
        return this;
    }

    /**
     * Returns the active value-to-percentage converter.
     *
     * @return the converter
     */
    public PercentConverter getPercentConverter()
    {
        return percentConverter;
    }

    /**
     * Returns the current value expressed as a percentage of the converter's range.
     *
     * @return percentage in [0..100]
     */
    public int currentPercent()
    {
        return percentConverter.iPercent(currentValue);
    }

    /**
     * Returns the current raw value.
     *
     * @return the raw value
     */
    public long currentValue()
    {
        return currentValue;
    }

    /** Refreshes the bar value, its interpolated color and the value label; must run on the EDT. */
    private void updateProgress()
    {
        int percent = percentConverter.iPercent(currentValue);
        progressBar.setValue(percent);

        // color the bar along the default gradient (0% -> 100%)
        progressBar.setForeground(GUIUtil.colorToRatio(percent / 100.0f));
        valueLabel.setText(""+currentValue);
    }

}
