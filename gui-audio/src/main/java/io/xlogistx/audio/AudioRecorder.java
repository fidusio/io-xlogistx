package io.xlogistx.audio;

import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.logging.LogWrapper;

import javax.sound.sampled.*;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.util.concurrent.atomic.AtomicBoolean;

public class AudioRecorder
implements AutoCloseable, Runnable
{
    public static final LogWrapper log = new LogWrapper(AudioRecorder.class).setEnabled(true);
    public enum Status
    {
        RECORDING,
        STOP_RECORDING,
        ERROR,
        CLOSED,
        PROCESSING,
        RESET,
    }

    private Status status = Status.STOP_RECORDING;
    private final UByteArrayOutputStream dataRecorder = new UByteArrayOutputStream();
    private final TargetDataLine dataLine;
    private final AudioFormat audioFormat;
    private final AtomicBoolean isClosed = new AtomicBoolean(false);
    private final DataLine.Info dataLineInfo;
    private final boolean dropSilence;

    public AudioRecorder(AudioFormat audioFormat, boolean dropSilence) throws LineUnavailableException {
        this.audioFormat = audioFormat;
        dataLineInfo = new DataLine.Info(TargetDataLine.class, audioFormat);
        if (!AudioSystem.isLineSupported(dataLineInfo))
            throw new IllegalArgumentException("The system does not support the specified format.");
        dataLine = (TargetDataLine) AudioSystem.getLine(dataLineInfo);
        this.dropSilence = dropSilence;
    }
    /**
     * Closes this resource, relinquishing any underlying resources.
     * This method is invoked automatically on objects managed by the
     * {@code try}-with-resources statement.
     *
     * <p>While this interface method is declared to throw {@code
     * Exception}, implementers are <em>strongly</em> encouraged to
     * declare concrete implementations of the {@code close} method to
     * throw more specific exceptions, or to throw no exception at all
     * if the close operation cannot fail.
     *
     * <p> Cases where the close operation may fail require careful
     * attention by implementers. It is strongly advised to relinquish
     * the underlying resources and to internally <em>mark</em> the
     * resource as closed, prior to throwing the exception. The {@code
     * close} method is unlikely to be invoked more than once and so
     * this ensures that the resources are released in a timely manner.
     * Furthermore it reduces problems that could arise when the resource
     * wraps, or is wrapped, by another resource.
     *
     * <p><em>Implementers of this interface are also strongly advised
     * to not have the {@code close} method throw {@link
     * InterruptedException}.</em>
     * <p>
     * This exception interacts with a thread's interrupted status,
     * and runtime misbehavior is likely to occur if an {@code
     * InterruptedException} is {@linkplain Throwable#addSuppressed
     * suppressed}.
     * <p>
     * More generally, if it would cause problems for an
     * exception to be suppressed, the {@code AutoCloseable.close}
     * method should not throw it.
     *
     * <p>Note that unlike the {@link Closeable#close close}
     * method of {@link Closeable}, this {@code close} method
     * is <em>not</em> required to be idempotent.  In other words,
     * calling this {@code close} method more than once may have some
     * visible side effect, unlike {@code Closeable.close} which is
     * required to have no effect if called more than once.
     * <p>
     * However, implementers of this interface are strongly encouraged
     * to make their {@code close} methods idempotent.
     *
     * @throws Exception if this resource cannot be closed
     */
    @Override
    public void close()
            throws Exception
    {
        if (!isClosed.getAndSet(true))
        {
            status = Status.CLOSED;
            if(dataLine != null && dataLine.isOpen())
            {
                dataLine.stop();
            }
            SharedIOUtil.close(dataLine);
        }
    }

    public Status getStatus()
    {
        return status;
    }


    public AudioRecorder setStatus(Status status, Runnable ...runnables)
    {
        setStatus(status);
        for (Runnable runnable: runnables)
            if(runnable != null)
            {
                runnable.run();
            }
        return this;
    }

    public synchronized AudioRecorder setStatus(Status status)
    {
        this.status = status;

        switch (status)
        {
            case RECORDING:
                dataLine.start();
                break;
            case RESET:
                break;
            case STOP_RECORDING:
                dataLine.stop();
                break;
            case ERROR:
                break;
            case CLOSED:
                break;
        }
        notifyAll();
        return this;
    }

    public synchronized boolean isRunning()
    {
        Status[] running = {
          Status.RECORDING,
          Status.STOP_RECORDING,
          Status.RESET,
          Status.PROCESSING
        };

        for(Status valid : running)
            if(status == valid)
                return true;

        return false;
    }


    public AudioRecorder reset()
    {
        return setStatus(Status.RESET);
    }

    public void run() {
        byte[] buffer = new byte[4096];
        try
        {
            dataLine.open(audioFormat);
            while (isRunning())
            {
                switch (status)
                {
                    case RECORDING:
                        synchronized (this)
                        {
                            AudioUtil.recordChunk(dataLine, dropSilence, dataRecorder, buffer);
                        }
                        break;
                    case RESET:
                        if(dataRecorder.size() > 0)
                            dataRecorder.reset();
                    case STOP_RECORDING:
                        synchronized (this)
                        {
                            try
                            {
                                wait(250);
                            }
                            catch (InterruptedException e)
                            {
                                e.printStackTrace();
                            }
                        }
                        break;
                }

            }
        }
        catch(Exception pe)
        {
            pe.printStackTrace();
            setStatus(Status.ERROR);
        }
        finally
        {
            if(dataLine != null)
                dataLine.stop();
        }

        log.getLogger().info("Finished Recording");
    }


    /**
     *
     * @return the recorded Stream based on the audio format null if no data available
     */
    public synchronized ByteArrayInputStream getRecordedStream()
    {
        if (dataRecorder.size() > 0)
        {
            return AudioUtil.createWavStream(dataRecorder, audioFormat);
        }
        return null;
    }

    public DataLine.Info getDataLineInfo()
    {
        return dataLineInfo;
    }


}
