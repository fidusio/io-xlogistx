package io.xlogistx.shared.security;


import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.security.SubjectAPIKey;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * Created on 7/14/17
 */
public class SubjectAPIKeyTest {

  @Test
  public void testSubjectAPIKeyTest()
      throws IOException, IllegalAccessException, ClassNotFoundException, InstantiationException, NoSuchAlgorithmException {
    SubjectAPIKey subjectAPIKey = new SubjectAPIKey();
    subjectAPIKey.setSubjectID(UUID.randomUUID().toString());
    subjectAPIKey.setAPIKey(CryptoUtil.generateKey( CryptoConst.CryptoAlgo.AES, 256).getEncoded());

    String json = GSONUtil.toJSON(subjectAPIKey, true);

    SubjectAPIKey fromJson = GSONUtil.fromJSON(json);
    System.out.println(fromJson);
  }

}
