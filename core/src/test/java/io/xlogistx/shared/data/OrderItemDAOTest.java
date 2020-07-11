package io.xlogistx.shared.data;




import org.junit.jupiter.api.Test;
import org.zoxweb.shared.accounting.AmountDAO;
import org.zoxweb.shared.accounting.Currency;
import org.zoxweb.shared.data.Range;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;


public class OrderItemDAOTest {

  @Test
  public void testItemQuantityDAO() {
    Range<Integer> rangeDAO1 = new Range<Integer>(1, 50);
    AmountDAO moneyValueDAO1 = new AmountDAO(new BigDecimal("10.00"), Currency.USD);
    PriceDAO priceDAO1 = new PriceDAO(rangeDAO1, moneyValueDAO1);

    Range rangeDAO2 = new Range<Integer>(51, 100);
    AmountDAO moneyValueDAO2 = new AmountDAO(new BigDecimal("8.00"), Currency.USD);
    PriceDAO priceDAO2 = new PriceDAO(rangeDAO2, moneyValueDAO2);

    Range rangeDAO3 = new Range<Integer>(101, 150);//new RangeDAO(new LimitValueDAO(101), new LimitValueDAO(150));
    AmountDAO moneyValueDAO3 = new AmountDAO(new BigDecimal("6.00"), Currency.USD);
    PriceDAO priceDAO3 = new PriceDAO(rangeDAO3, moneyValueDAO3);

    Range rangeDAO4 = new Range<Integer>(151, 200);//new RangeDAO(new LimitValueDAO(151), new LimitValueDAO(200));
    AmountDAO moneyValueDAO4 = new AmountDAO(new BigDecimal("4.00"), Currency.USD);
    PriceDAO priceDAO4 = new PriceDAO(rangeDAO4, moneyValueDAO4);

    Range rangeDAO5 = new Range<Integer>(201, Integer.MAX_VALUE);//new RangeDAO(new LimitValueDAO(201),new LimitValueDAO(LimitValueDAO.LimitType.OPEN_VALUE));
    AmountDAO moneyValueDAO5 = new AmountDAO(new BigDecimal("2.00"), Currency.USD);
    PriceDAO priceDAO5 = new PriceDAO(rangeDAO5, moneyValueDAO5);

    PriceRangeDAO priceRangeDAO = new PriceRangeDAO();
    priceRangeDAO.getPriceList().add(priceDAO1);
    priceRangeDAO.getPriceList().add(priceDAO2);
    priceRangeDAO.getPriceList().add(priceDAO3);
    priceRangeDAO.getPriceList().add(priceDAO4);
    priceRangeDAO.getPriceList().add(priceDAO5);

    ItemDAO itemDAO = new ItemDAO();
    itemDAO.setDescription("Item A");
    itemDAO.setPriceRange(priceRangeDAO);

    OrderItemDAO orderItemDAO1 = new OrderItemDAO();
    orderItemDAO1.setItem(itemDAO);
    orderItemDAO1.setQuantity(50);
    AmountDAO total = XXDataUtil.computeTotal(orderItemDAO1);
    assertNotNull(total);
    assertNotNull(total.getAmount());
    assertEquals("$500.00", total.toString());

    OrderItemDAO orderItemDAO2 = new OrderItemDAO();
    orderItemDAO2.setItem(itemDAO);
    orderItemDAO2.setQuantity(150);
    total = XXDataUtil.computeTotal(orderItemDAO2);
    assertNotNull(total);
    assertNotNull(total.getAmount());
    assertEquals("$900.00", total.toString());

    OrderItemDAO orderItemDAO3 = new OrderItemDAO();
    orderItemDAO3.setItem(itemDAO);
    orderItemDAO3.setQuantity(400);
    total = XXDataUtil.computeTotal(orderItemDAO3);
    assertNotNull(total);
    assertNotNull(total.getAmount());
    assertEquals("$800.00", total.toString());
  }

}