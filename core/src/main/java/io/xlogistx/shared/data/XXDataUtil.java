package io.xlogistx.shared.data;

import org.zoxweb.shared.accounting.AmountDAO;

import java.math.BigDecimal;

public final class XXDataUtil {

  private XXDataUtil() {

  }

  public static boolean isWithinPriceRange(PriceDAO priceDAO, int quantity) {
    if (priceDAO != null && priceDAO.getRange() != null) {
      return priceDAO.getRange().within(quantity);
    }
//    if (priceDAO != null && priceDAO.getRange() != null
//        && priceDAO.getRange().getStart() != null && priceDAO.getRange().getEnd() != null) {
//      LimitValueDAO rangeStart = priceDAO.getRange().getStart();
//      LimitValueDAO rangeEnd = priceDAO.getRange().getEnd();
//
//      boolean higherThanStart = false;
//      boolean lowerThanEnd = false;
//
//      if (rangeStart.getLimitType() != null
//          && rangeStart.getLimitType() == LimitValueDAO.LimitType.OPEN_VALUE) {
//        higherThanStart = true;
//      } else {
//        if (rangeStart.isExclusive()) {
//          higherThanStart = quantity > rangeStart.getValue();
//        } else {
//          higherThanStart = quantity >= rangeStart.getValue();
//        }
//      }
//
//      if (rangeEnd.getLimitType() != null
//          && rangeEnd.getLimitType() == LimitValueDAO.LimitType.OPEN_VALUE) {
//        lowerThanEnd = true;
//      } else {
//        if (rangeEnd.isExclusive()) {
//          lowerThanEnd = quantity < rangeEnd.getValue();
//        } else {
//          lowerThanEnd = quantity <= rangeEnd.getValue();
//        }
//      }
//
//      if (higherThanStart && lowerThanEnd) {
//        return true;
//      }
//    }

    return false;
  }


  public static int getLowestRangeValue(PriceRangeDAO priceRange)
  {
    Integer lowest = null;
    if (priceRange != null && priceRange.getPriceList() != null)
    {
      for (PriceDAO price : priceRange.getPriceList())
      {

        int currentLow = (Integer) price.getRange().getStart();
        if (lowest == null)
        {
          lowest = currentLow;
          continue;
        }
        if (currentLow < lowest)
        {
          lowest = currentLow;
        }
      }
    }

    return lowest;
  }


  public static int getHighestRangeValue(PriceRangeDAO priceRange)
  {
    Integer highest = null;
    if (priceRange != null && priceRange.getPriceList() != null)
    {
      for (PriceDAO price : priceRange.getPriceList())
      {

        int currentHigh = (Integer) price.getRange().getEnd();
        if (highest == null)
        {
          highest = currentHigh;
          continue;
        }
        if (currentHigh > highest)
        {
          highest = currentHigh;
        }
      }
    }

    return highest;
  }

  public static AmountDAO calculatePrice(PriceRangeDAO priceRangeDAO, int quantity) {
    if (priceRangeDAO != null && priceRangeDAO.getPriceList() != null) {
      for (PriceDAO priceDAO : priceRangeDAO.getPriceList()) {
        if (isWithinPriceRange(priceDAO, quantity)) {
          return priceDAO.getPrice();
        }
      }
    }

    return null;
  }

  public static AmountDAO computeTotal(OrderDAO orderDAO) {
    BigDecimal value = new BigDecimal(0);

    if (orderDAO != null && orderDAO.getOrderItems() != null) {
      for (OrderItemDAO orderItemDAO : orderDAO.getOrderItems()) {
        value = value.add(computeTotal(orderItemDAO).getAmount());
      }
    }

    return new AmountDAO(value);
  }

  public static AmountDAO computeTotal(OrderItemDAO orderItemDAO) {
    AmountDAO total = new AmountDAO();

    if (orderItemDAO != null && orderItemDAO.getItem() != null
        && orderItemDAO.getItem().getPriceRange() != null) {
      AmountDAO itemPrice = calculatePrice(orderItemDAO.getItem().getPriceRange(),
          orderItemDAO.getQuantity());

      if (itemPrice != null) {
        total.setAmount(itemPrice.getAmount().multiply(new BigDecimal(orderItemDAO.getQuantity())));
      }
    }

    return total;
  }


  public static OrderDAO updateTotal(OrderDAO orderDAO) {
    if (orderDAO != null) {
      orderDAO.setTotal(computeTotal(orderDAO));

      return orderDAO;
    }

    return null;
  }

  public static OrderItemDAO updateTotal(OrderItemDAO orderItemDAO) {
    if (orderItemDAO != null) {
      orderItemDAO.setTotal(computeTotal(orderItemDAO));

      return orderItemDAO;
    }

    return null;
  }

}
