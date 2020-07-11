package io.xlogistx.shared.data;


import org.junit.jupiter.api.Test;
import org.zoxweb.shared.accounting.AmountDAO;
import org.zoxweb.shared.accounting.Currency;
import org.zoxweb.shared.data.Range;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.*;


public class PriceDAOTest {

  @Test
  public void testPriceDAO() {
    AmountDAO moneyValueDAO = new AmountDAO(new BigDecimal("1000.00"));
    assertEquals("$1000.00", moneyValueDAO.toString());

    Range<Integer> rangeDAO = new Range<Integer>(1, 100);
    PriceDAO priceDAO = new PriceDAO(rangeDAO, moneyValueDAO);

    XXDataUtil.isWithinPriceRange(priceDAO, 0);

    assertFalse(XXDataUtil.isWithinPriceRange(priceDAO, 0));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 1));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 10));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 25));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 50));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 100));
    assertFalse(XXDataUtil.isWithinPriceRange(priceDAO, 101));
    assertFalse(XXDataUtil.isWithinPriceRange(priceDAO, 1000));

    rangeDAO = new Range<Integer>(1, 100, Range.Inclusive.START);//(new LimitValueDAO(1), new LimitValueDAO(100, true));
    priceDAO = new PriceDAO(rangeDAO, moneyValueDAO);

    assertFalse(XXDataUtil.isWithinPriceRange(priceDAO, 0));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 1));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 10));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 25));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 50));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 99));
    assertFalse(XXDataUtil.isWithinPriceRange(priceDAO, 100));
    assertFalse(XXDataUtil.isWithinPriceRange(priceDAO, 101));
    assertFalse(XXDataUtil.isWithinPriceRange(priceDAO, 1000));


//    rangeDAO = new RangeDAO(new LimitValueDAO(1),
//        new LimitValueDAO(LimitValueDAO.LimitType.OPEN_VALUE));
    rangeDAO = new Range<Integer>(1, Integer.MAX_VALUE);
    priceDAO = new PriceDAO(rangeDAO, moneyValueDAO);

    assertFalse(XXDataUtil.isWithinPriceRange(priceDAO, 0));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 1));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 10));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 25));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 50));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 99));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 100));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 101));
    assertTrue(XXDataUtil.isWithinPriceRange(priceDAO, 1000));
  }

  @Test
  public void testPriceRangeDAO() {
    // 1
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
    assertNotNull(priceRangeDAO.getPriceList());
    assertTrue(priceRangeDAO.getPriceList().isEmpty());
    priceRangeDAO.getPriceList().add(priceDAO1);
    priceRangeDAO.getPriceList().add(priceDAO2);
    priceRangeDAO.getPriceList().add(priceDAO3);
    priceRangeDAO.getPriceList().add(priceDAO4);
    priceRangeDAO.getPriceList().add(priceDAO5);
    assertEquals(5, priceRangeDAO.getPriceList().size());

    AmountDAO price = XXDataUtil.calculatePrice(priceRangeDAO, 1);
    assertNotNull(price);
    assertEquals("$10.00", price.toString());

    price = XXDataUtil.calculatePrice(priceRangeDAO, 50);
    assertNotNull(price);
    assertEquals("$10.00", price.toString());

    price = XXDataUtil.calculatePrice(priceRangeDAO, 75);
    assertNotNull(price);
    assertEquals("$8.00", price.toString());

    price = XXDataUtil.calculatePrice(priceRangeDAO, 100);
    assertNotNull(price);
    assertEquals("$8.00", price.toString());

    price = XXDataUtil.calculatePrice(priceRangeDAO, 150);
    assertNotNull(price);
    assertEquals("$6.00", price.toString());

    price = XXDataUtil.calculatePrice(priceRangeDAO, 175);
    assertNotNull(price);
    assertEquals("$4.00", price.toString());

    price = XXDataUtil.calculatePrice(priceRangeDAO, 200);
    assertNotNull(price);
    assertEquals("$4.00", price.toString());

    price = XXDataUtil.calculatePrice(priceRangeDAO, 400);
    assertNotNull(price);
    assertEquals("$2.00", price.toString());

    price = XXDataUtil.calculatePrice(priceRangeDAO, 0);
    assertNull(price);
  }

}