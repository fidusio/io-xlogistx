package io.xlogistx.shared.data;


import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.accounting.AmountInfo;
import org.zoxweb.shared.accounting.Currency;
import org.zoxweb.shared.data.ImageMetaInfo;
import org.zoxweb.shared.data.Range;


import java.io.IOException;
import java.math.BigDecimal;

public class ItemTest {
    @Test
    public void createItem() throws IOException {
        String baseURL = "http://localhost";
        String appGID = "test.com-batata";

        Range<Integer> rangeDAO1 = new Range<Integer>(1, 2);
        AmountInfo moneyValueDAO1 = new AmountInfo(new BigDecimal("25.00"), Currency.USD);
        PriceDAO priceDAO1 = new PriceDAO(rangeDAO1, moneyValueDAO1);

        Range<Integer> rangeDAO2 = new Range<Integer>(3, 5);
        AmountInfo moneyValueDAO2 = new AmountInfo(new BigDecimal("22.50"), Currency.USD);
        PriceDAO priceDAO2 = new PriceDAO(rangeDAO2, moneyValueDAO2);

        Range<Integer> rangeDAO3 = new Range<Integer>(6, 7);
        AmountInfo moneyValueDAO3 = new AmountInfo(new BigDecimal("20.00"), Currency.USD);
        PriceDAO priceDAO3 = new PriceDAO(rangeDAO3, moneyValueDAO3);

        Range<Integer> rangeDAO4 = new Range<Integer>(8, 14);
        AmountInfo moneyValueDAO4 = new AmountInfo(new BigDecimal("16.00"), Currency.USD);
        PriceDAO priceDAO4 = new PriceDAO(rangeDAO4, moneyValueDAO4);

        Range<Integer> rangeDAO5 = new Range<Integer>(15, 20);
        AmountInfo moneyValueDAO5 = new AmountInfo(new BigDecimal("15.00"), Currency.USD);
        PriceDAO priceDAO5 = new PriceDAO(rangeDAO5, moneyValueDAO5);

        Range<Integer> rangeDAO6 = new Range<Integer>(21, 24);
        AmountInfo moneyValueDAO6 = new AmountInfo(new BigDecimal("14.00"), Currency.USD);
        PriceDAO priceDAO6 = new PriceDAO(rangeDAO6, moneyValueDAO6);

        Range<Integer> rangeDAO7 = new Range<Integer>(25, 500);
        AmountInfo moneyValueDAO7 = new AmountInfo(new BigDecimal("13.00"), Currency.USD);
        PriceDAO priceDAO7 = new PriceDAO(rangeDAO7, moneyValueDAO7);

        PriceRangeDAO priceRangeDAO = new PriceRangeDAO();
        priceRangeDAO.getPriceList().add(priceDAO1);
        priceRangeDAO.getPriceList().add(priceDAO2);
        priceRangeDAO.getPriceList().add(priceDAO3);
        priceRangeDAO.getPriceList().add(priceDAO4);
        priceRangeDAO.getPriceList().add(priceDAO5);
        priceRangeDAO.getPriceList().add(priceDAO6);
        priceRangeDAO.getPriceList().add(priceDAO7);

        ImageMetaInfo imageDAO = new ImageMetaInfo();
        imageDAO.setFormat(ImageMetaInfo.ImageFormat.IMAGE_PNG);
        imageDAO.setName("item-tank.png");
        imageDAO.setResourceLocator(baseURL + "/images/pxp/item-tank.png");
        //imageDAO.setResourceLocator(baseURL + "" + XXURI.IMAGE + "/" + appIDDAO.getDomainID() + "/" + appIDDAO.getAppID() + "/item-tank.png");

        ItemDAO itemDAO = new ItemDAO();
        itemDAO.setDomainAppID("test.com", "batata");
        itemDAO.setDescription("20 LB Propane Tank - Exchange");
        itemDAO.setPriceRange(priceRangeDAO);
        itemDAO.getImages().add(imageDAO);


        String json = GSONUtil.toJSON(itemDAO,true, false, false);
        System.out.println(json);
        ItemDAO itemDAO2 = GSONUtil.fromJSON(json, ItemDAO.class);
        assert(GSONUtil.toJSON(itemDAO,true, false, true).equals(GSONUtil.toJSON(itemDAO2,true, false, true)));

    }
}
