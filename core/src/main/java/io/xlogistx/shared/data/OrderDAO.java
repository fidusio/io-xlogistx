package io.xlogistx.shared.data;

import io.xlogistx.shared.util.XXStatus;
import org.zoxweb.shared.accounting.AmountDAO;
import org.zoxweb.shared.data.AddressDAO;
import org.zoxweb.shared.data.AppIDResource;
import org.zoxweb.shared.util.*;

import java.util.Date;
import java.util.List;

@SuppressWarnings("serial")
public class OrderDAO
        extends AppIDResource {

    public enum Param
            implements GetNVConfig {


        ORDER_ID(NVConfigManager
                .createNVConfig("order_id", "Order ID", "OrderID", false, false, String.class)),
        ORDER_STATUS(NVConfigManager
                .createNVConfig("order_status", "Order status", "OrderStatus", true, false,
                        XXStatus.class)),
        ORDER_ITEMS(NVConfigManager
                .createNVConfigEntity("order_items", "List of order items", "OrderItems", true, true,
                        OrderItemDAO.NVC_ORDER_ITEM_DAO, NVConfigEntity.ArrayType.LIST)),
        TOTAL(NVConfigManager
                .createNVConfigEntity("total", "Total", "Total", true, true, AmountDAO.class,
                        NVConfigEntity.ArrayType.NOT_ARRAY)),
        DELIVERY_TIMESTAMP(NVConfigManager
                .createNVConfig("delivery_timestamp", "Delivery timestamp.", "DeliveryTimestamp", false,
                        true, Date.class)),
        DELIVERY_ADDRESS(NVConfigManager
                .createNVConfigEntity("delivery_address", "Delivery address", "DeliveryAddress", true, true,
                        AddressDAO.class, NVConfigEntity.ArrayType.NOT_ARRAY)),

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

    public static final NVConfigEntity NVC_ORDER_DAO = new NVConfigEntityPortable(
            "order_dao",
            null,
            OrderDAO.class.getSimpleName(),
            true,
            false,
            false,
            false,
            OrderDAO.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            AppIDResource.NVC_APP_ID_RESOURCE
    );

    public OrderDAO() {
        super(NVC_ORDER_DAO);
    }


    /**
     * Returns the order ID.
     */
    public String getOrderID() {
        return lookupValue(Param.ORDER_ID);
    }

    /**
     * Sets the order ID.
     */
    public void setOrderID(String orderID) {
        setValue(Param.ORDER_ID, orderID);
    }

    /**
     * Returns the order status.
     */
    public XXStatus getOrderStatus() {
        return lookupValue(Param.ORDER_STATUS);
    }

    /**
     * Sets the order status.
     */
    public void setOrderStatus(XXStatus status) {
        setValue(Param.ORDER_STATUS, status);
    }


    /**
     * Returns the items.
     */
    public List<OrderItemDAO> getOrderItems() {
        return lookupValue(Param.ORDER_ITEMS);
    }

    /**
     * Sets the items.
     */
    public void setOrderItems(List<OrderItemDAO> list) {
        setValue(Param.ORDER_ITEMS, list);
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


    /**
     * Returns the delivery timestamp.
     */
    public long getDeliveryTimestamp() {
        return lookupValue(Param.DELIVERY_TIMESTAMP);
    }

    /**
     * Sets the delivery timestamp.
     */
    public void setDeliveryTimestamp(long deliveryTimestamp) {
        setValue(Param.DELIVERY_TIMESTAMP, deliveryTimestamp);
    }

    /**
     * Returns the delivery address.
     */
    public AddressDAO getDeliveryAddress() {
        return lookupValue(Param.DELIVERY_ADDRESS);
    }

    /**
     * Sets the delivery address.
     */
    public void setDeliveryAddress(AddressDAO address) {
        setValue(Param.DELIVERY_ADDRESS, address);
    }


}