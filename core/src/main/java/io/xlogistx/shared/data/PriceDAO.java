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

import org.zoxweb.shared.accounting.AmountDAO;
import org.zoxweb.shared.data.Range;
import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.*;

@SuppressWarnings("serial")
public class PriceDAO
    extends SetNameDescriptionDAO {

  public enum Param
      implements GetNVConfig {
    RANGE(NVConfigManager
        .createNVConfigEntity("range", "Range", "Range", true, true, Range.class,
            NVConfigEntity.ArrayType.NOT_ARRAY)),
    PRICE(NVConfigManager
        .createNVConfigEntity("price", "Price", "Price", true, true, AmountDAO.class,
            NVConfigEntity.ArrayType.NOT_ARRAY)),

    ;

    private final NVConfig nvc;

    Param(NVConfig nvc) {
      this.nvc = nvc;
    }

    @Override
    public NVConfig getNVConfig() {
      return nvc;
    }
  }

  public static final NVConfigEntity NVC_PRICE_DAO = new NVConfigEntityLocal(
      "price_dao",
      null,
      PriceDAO.class.getSimpleName(),
      true,
      false,
      false,
      false,
      PriceDAO.class,
      SharedUtil.extractNVConfigs(Param.values()),
      null,
      false,
      SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
  );


  public PriceDAO() {
    super(NVC_PRICE_DAO);
  }

  public PriceDAO(Range range, AmountDAO price) {
    this();
    setRange(range);
    setPrice(price);
  }

  /**
   * Returns the range.
   */
  public Range getRange() {
    return lookupValue(Param.RANGE);
  }

  /**
   * Sets the range.
   */
  public void setRange(Range range) {
    setValue(Param.RANGE, range);
  }

  /**
   * Returns the price
   */
  public AmountDAO getPrice() {
    return lookupValue(Param.PRICE);
  }

  /**
   * Sets the price.
   */
  public void setPrice(AmountDAO price) {
    setValue(Param.PRICE, price);
  }

  @Override
  public String toString() {
    return getRange() + " : " + getPrice();
  }

}