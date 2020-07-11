package io.xlogistx.shared.util;


import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XXURITest {

  @Test
  public void testFormatURI() {
    XXURI.SINGLETON.setPreURI("https://api.xlogistx.io");
    String fullLoginURI = XXURI.SINGLETON.formatURI(XXURI.LOGIN);
    assertEquals("https://api.xlogistx.io/v1/login", fullLoginURI);
  }
}
