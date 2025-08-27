package io.xlogistx.shared.data;

import org.zoxweb.shared.accounting.AmountDAO;
import org.zoxweb.shared.accounting.PaymentInfoDAO;
import org.zoxweb.shared.accounting.TransactionStatus;
import org.zoxweb.shared.accounting.TransactionType;
import org.zoxweb.shared.data.AppIDResource;
import org.zoxweb.shared.util.*;

@SuppressWarnings("serial")
public class OrderTransactionDAO
        extends AppIDResource {

    public enum Param
            implements GetNVConfig {
        ORDER(NVConfigManager
                .createNVConfigEntity("order", "Order", "Order", true, true, OrderDAO.class,
                        NVConfigEntity.ArrayType.NOT_ARRAY)),
        PAYMENT_INFO(NVConfigManager
                .createNVConfigEntity("payment_info", "Payment info", "PaymentInfo", true, true,
                        PaymentInfoDAO.class, NVConfigEntity.ArrayType.NOT_ARRAY)),
        TRANSACTION_AMOUNT(NVConfigManager
                .createNVConfigEntity("transaction_amount", "Transaction amount", "TransactionAmount", true,
                        true, AmountDAO.NVC_AMOUNT_DAO)),
        TRANSACTION_TYPE(NVConfigManager
                .createNVConfig("transaction_type", "Type of transaction either credit or debit",
                        "TransactionType", false, true, TransactionType.class)),
        TRANSACTION_DESCRIPTOR(NVConfigManager
                .createNVConfig("transaction_descriptor", "Description of transaction",
                        "TransactionDescriptor", false, true, String.class)),
        TRANSACTION_STATUS(NVConfigManager
                .createNVConfig("transaction_status", "Transaction status", "TransactionStatus", false,
                        true, TransactionStatus.class)),

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

    public static final NVConfigEntity NVC_ORDER_TRANSACTION_DAO = new NVConfigEntityPortable(
            "order_transaction_dao",
            null,
            OrderTransactionDAO.class.getSimpleName(),
            true,
            false,
            false,
            false,
            OrderTransactionDAO.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            AppIDResource.NVC_APP_ID_RESOURCE
    );

    public OrderTransactionDAO() {
        super(NVC_ORDER_TRANSACTION_DAO);
    }


    /**
     * Returns the order.
     */
    public OrderDAO getOrder() {
        return lookupValue(Param.ORDER);
    }

    /**
     * Sets the order.
     */
    public void setOrder(OrderDAO order) {
        setValue(Param.ORDER, order);
    }

    /**
     * Returns the payment info.
     */
    public PaymentInfoDAO getPaymentInfo() {
        return lookupValue(Param.PAYMENT_INFO);
    }

    /**
     * Sets the payment info.
     */
    public void setPaymentInfo(PaymentInfoDAO paymentInfo) {
        setValue(Param.PAYMENT_INFO, paymentInfo);
    }

    /**
     * Returns the transaction amount.
     */
    public AmountDAO getTransactionAmount() {
        return lookupValue(Param.TRANSACTION_AMOUNT);
    }

    /**
     * Sets the transaction amount.
     */
    public void setTransactionAmount(AmountDAO amount) {
        setValue(Param.TRANSACTION_AMOUNT, amount);
    }

    /**
     * Returns the transaction type.
     */
    public TransactionType getTransactionType() {
        return lookupValue(Param.TRANSACTION_TYPE);
    }

    /**
     * Sets the transaction type.
     */
    public void setTransactionType(TransactionType type) {
        setValue(Param.TRANSACTION_TYPE, type);
    }

    /**
     * Returns the transaction descriptor.
     */
    public String getTransactionDescriptor() {
        return lookupValue(Param.TRANSACTION_DESCRIPTOR);
    }

    /**
     * Sets the transaction descriptor.
     */
    public void setTransactionDescriptor(String descriptor) {
        setValue(Param.TRANSACTION_DESCRIPTOR, descriptor);
    }

    /**
     * Returns the transaction status.
     */
    public String getTransactionStatus() {
        return lookupValue(Param.TRANSACTION_STATUS);
    }

    /**
     * Sets the transaction status.
     */
    public void setTransactionStatus(TransactionStatus status) {
        setValue(Param.TRANSACTION_STATUS, status);
    }

}