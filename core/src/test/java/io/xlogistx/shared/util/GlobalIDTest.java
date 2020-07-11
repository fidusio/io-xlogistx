package io.xlogistx.shared.util;


import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GlobalIDTest {

  private static final String ORDER_ID = "1000000";
  private static final String GLOBAL_ID = "b322b1fe-092e-4ca1-9aee-683c12297c28";

  @Test
  public void testValidOrderID() {
    assertTrue(XXUtil.isOrderID(ORDER_ID));
  }

  @Test
  public void testInvalidOrderID() {
    assertFalse(XXUtil.isOrderID(GLOBAL_ID));
  }

  @Test
  public void testValidGlobalID() {
    assertTrue(XXUtil.isGlobalID(GLOBAL_ID));
  }

  @Test
  public void testInvalidGlobalID() {
    assertFalse(XXUtil.isGlobalID(ORDER_ID));
  }

}