/*
 * Copyright (c) 2012-2017 ZoxWeb.com LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.xlogistx.shared.data;

import org.junit.jupiter.api.Test;
import org.zoxweb.shared.data.Range;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;


public class RangeDAOTest {


  @Test
  public void testInclusiveRange() {


    Range range = new Range(1, 100, Range.Inclusive.BOTH);
    assertNotNull(range.getStart());
    assertNotNull(range.getEnd());
    assertEquals("[1, 100]", range.toString());

    System.out.println(range);
  }


  @Test
  public void testExclusiveRange() {

    Range range = new Range(1, 100, Range.Inclusive.START);
    assertNotNull(range.getStart());
    assertNotNull(range.getEnd());
    assertEquals("[1, 100)", range.toString());

    System.out.println(range);
  }


  @Test
  public void testOpenValueRange() {



    Range range = new Range(1, Integer.MAX_VALUE, Range.Inclusive.START);
    assertNotNull(range.getStart());
    assertNotNull(range.getEnd());
    assertEquals("[1, 2147483647)", range.toString());

    System.out.println(range);
  }

}