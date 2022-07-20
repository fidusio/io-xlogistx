package io.xlogistx.common.data;

import org.zoxweb.server.task.TaskUtil;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class ChallengeManager {
    private static final Logger log = Logger.getLogger(ChallengeManager.class.getName());
    public static final ChallengeManager SINGLETON = new ChallengeManager();

    private Map<String, Challenge> challengeMap = new ConcurrentHashMap<String, Challenge>();

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
                TaskUtil.getDefaultTaskScheduler().queue(timeout, ()->{
                   log.info("Challenge removed: " + removeChallenge(challenge.getId()));
                });
            }
        }
    }


    public Challenge lookupChallenge(String id)
    {
        return challengeMap.get(id);
    }


    public synchronized Challenge removeChallenge(String id)
    {
        return challengeMap.remove(id);
    }


    public Challenge removeChallenge(Challenge challenge)
    {
        if(challenge != null)
            return removeChallenge(challenge.getId());
        return null;
    }

    public synchronized boolean validate(String id, long result)
    {
        Challenge challenge = lookupChallenge(id);
        if (challenge != null)
        {
            removeChallenge(id);
            return challenge.getResult() == result;
        }

        return false;
    }


    public synchronized boolean validate(Challenge ch, long result)
    {
        if(ch != null)
            return validate(ch.getId(), result);

        return false;
    }

}
