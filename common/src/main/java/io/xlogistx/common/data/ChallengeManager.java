package io.xlogistx.common.data;

import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.task.TaskUtil;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class ChallengeManager {


    private static final Logger log = Logger.getLogger(ChallengeManager.class.getName());
    public static final ChallengeManager SINGLETON = new ChallengeManager();

    private final Map<String, Challenge> challengeMap = new ConcurrentHashMap<>();

    private ChallengeManager()
    {

    }


    public synchronized void addChallenge(Challenge challenge, long timeout)
    {
        if(challenge != null)
        {
            challengeMap.put(challenge.getId(), challenge);
            if(timeout > 0)
            {
                String challengeID = challenge.getId();
                challenge.setAppointment(TaskUtil.defaultTaskScheduler().queue(timeout, ()->{
                   log.info("Challenge removed: " + removeChallenge(challengeID));
                }));
            }
        }
    }


    public Challenge[] getAll()
    {
        return challengeMap.values().toArray(new Challenge[0]);
    }

    public Challenge lookupChallenge(String id)
    {
        return challengeMap.get(id);
    }


    public synchronized Challenge removeChallenge(String id)
    {
        return challengeMap.remove(id);

    }

    public int size()
    {
        return challengeMap.size();
    }


    public Challenge removeChallenge(Challenge challenge)
    {
        if(challenge != null)
            return removeChallenge(challenge.getId());
        return null;
    }

    public synchronized boolean validate(String id, long result)
    {
        boolean validation = false;
        Challenge challenge = lookupChallenge(id);
        if (challenge != null)
        {
            removeChallenge(id);
            // cancel the appointment
            IOUtil.close(challenge.getAppointment());
            validation = challenge.getResult() == result;
            log.info(challenge.getId() + " validation status " + validation);
        }

        return validation;
    }


    public synchronized boolean validate(Challenge ch, long result)
    {
        if(ch != null)
            return validate(ch.getId(), result);

        return false;
    }

}
