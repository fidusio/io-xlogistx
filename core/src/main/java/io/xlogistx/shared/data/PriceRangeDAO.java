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

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.*;

import java.util.List;

@SuppressWarnings("serial")
public class PriceRangeDAO
        extends SetNameDescriptionDAO {

    public enum Param
            implements GetNVConfig {
        PRICE_LIST(NVConfigManager
                .createNVConfigEntity("price_list", "List of prices", "Prices", false, true,
                        PriceDAO.NVC_PRICE_DAO, NVConfigEntity.ArrayType.LIST)),

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

    public static final NVConfigEntity NVC_PRICE_RANGE_DAO = new NVConfigEntityPortable(
            "price_range_dao",
            null,
            PriceRangeDAO.class.getSimpleName(),
            true,
            false,
            false,
            false,
            PriceRangeDAO.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
    );


    public PriceRangeDAO() {
        super(NVC_PRICE_RANGE_DAO);
    }

    /**
     * Returns list of prices.
     */
    public List<PriceDAO> getPriceList() {
        return lookupValue(Param.PRICE_LIST);
    }

    /**
     * Sets list of prices.
     */
    public void setPriceList(List<PriceDAO> list) {
        setValue(Param.PRICE_LIST, list);
    }

}