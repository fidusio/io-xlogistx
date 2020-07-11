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
import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.*;

@SuppressWarnings("serial")
public class OrderItemDAO
    extends SetNameDescriptionDAO {

  public enum Param
      implements GetNVConfig {

    ITEM(NVConfigManager.createNVConfigEntity("item", "Item", "Item", true, true, ItemDAO.class,
        NVConfigEntity.ArrayType.NOT_ARRAY)),
    QUANTITY(
        NVConfigManager.createNVConfig("quantity", "Quantity", "Quantity", true, true, int.class)),
    TOTAL(NVConfigManager
        .createNVConfigEntity("total", "Total", "Total", true, true, AmountDAO.class,
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

  public static final NVConfigEntity NVC_ORDER_ITEM_DAO = new NVConfigEntityLocal(
      "order_item_dao",
      null,
      OrderItemDAO.class.getSimpleName(),
      true,
      false,
      false,
      false,
      OrderItemDAO.class,
      SharedUtil.extractNVConfigs(Param.values()),
      null,
      false,
      SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
  );

  public OrderItemDAO() {
    super(NVC_ORDER_ITEM_DAO);
  }

  /**
   * Returns the item.
   */
  public ItemDAO getItem() {
    return lookupValue(Param.ITEM);
  }

  /**
   * Sets the item.
   */
  public void setItem(ItemDAO item) {
    setValue(Param.ITEM, item);
  }

  /**
   * Returns the quantity.
   */
  public int getQuantity() {
    return lookupValue(Param.QUANTITY);
  }

  /**
   * Sets the quantity.
   */
  public void setQuantity(int quantity) {
    setValue(Param.QUANTITY, quantity);
  }

  /**
   * Returns the total.
   */
  public AmountDAO getTotal() {
    return lookupValue(Param.TOTAL);
  }

  /**
   * Sets the total.
   */
  public void setTotal(AmountDAO total) {
    setValue(Param.TOTAL, total);
  }

}