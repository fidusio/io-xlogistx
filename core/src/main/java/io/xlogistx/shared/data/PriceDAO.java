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

import org.zoxweb.shared.accounting.AmountInfo;
import org.zoxweb.shared.data.Range;
import org.zoxweb.shared.data.SetNameDescriptionImpl;
import org.zoxweb.shared.util.*;

@SuppressWarnings("serial")
public class PriceDAO
        extends SetNameDescriptionImpl {

    public enum Param
            implements GetNVConfig {
        RANGE(NVConfigManager
                .createNVConfigEntity("range", "Range", "Range", true, true, Range.class,
                        NVConfigEntity.ArrayType.NOT_ARRAY)),
        PRICE(NVConfigManager
                .createNVConfigEntity("price", "Price", "Price", true, true, AmountInfo.class,
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

    public static final NVConfigEntity NVC_PRICE_DAO = new NVConfigEntityPortable(
            "price_dao",
            null,
            PriceDAO.class.getSimpleName(),
            true,
            false,
            false,
            false,
            PriceDAO.class,
            SUS.extractNVConfigs(Param.values()),
            null,
            false,
            SetNameDescriptionImpl.NVC_NAME_DESCRIPTION_IMPL
    );


    public PriceDAO() {
        super(NVC_PRICE_DAO);
    }

    public PriceDAO(Range range, AmountInfo price) {
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
    public AmountInfo getPrice() {
        return lookupValue(Param.PRICE);
    }

    /**
     * Sets the price.
     */
    public void setPrice(AmountInfo price) {
        setValue(Param.PRICE, price);
    }

    @Override
    public String toString() {
        return getRange() + " : " + getPrice();
    }

}