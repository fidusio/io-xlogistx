package io.xlogistx.shiro;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.SubjectThreadState;

/**
 * This class swap the current subject with the subject to swap with the current execution thread.
 * It is via the constructor, if the toSwapWith is null nothing is done
 * @author mnael
 *
 */
public class SubjectSwap
        implements AutoCloseable
{
    public static final String SUBJECT_SWAP = "subject-swap";

    private SubjectThreadState subjectThreadState;

    public SubjectSwap(Subject toSwapWith)
    {
        if (toSwapWith != null)
        {
            subjectThreadState = new SubjectThreadState(toSwapWith);
            subjectThreadState.bind();
        }
        else
        {
            subjectThreadState = null;
        }
    }

    /**
     * Restore the previous subject context
     */
    @Override
    public void close()
    {
        if (subjectThreadState != null)
        {
            synchronized (this)
            {
                if (subjectThreadState != null)
                {
                    subjectThreadState.restore();
                    subjectThreadState = null;
                }
            }
        }
    }

}