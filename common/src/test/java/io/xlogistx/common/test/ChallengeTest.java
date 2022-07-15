package io.xlogistx.common.test;

import io.xlogistx.common.data.Challenge;
import org.junit.jupiter.api.Test;

import java.util.UUID;

public class ChallengeTest {

    @Test
    public void testTypes()
    {
        for(Challenge.Type t : Challenge.Type.values())
        {
            Challenge challenge = Challenge.generate(t, t.ordinal() + 2, UUID.randomUUID().toString());
            System.out.println(challenge.format() + "    " + challenge);

        }
    }
}
