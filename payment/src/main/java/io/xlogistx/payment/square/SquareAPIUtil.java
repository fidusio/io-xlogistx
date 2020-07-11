package io.xlogistx.payment.square;

import java.math.BigDecimal;
import java.util.List;

//import com.squareup.connect.ApiClient;
//import com.squareup.connect.ApiException;
//import com.squareup.connect.Configuration;
//import com.squareup.connect.api.LocationsApi;
//import com.squareup.connect.api.TransactionsApi;
//import com.squareup.connect.auth.OAuth;
//import com.squareup.connect.models.ChargeRequest;
//import com.squareup.connect.models.ChargeResponse;
//import com.squareup.connect.models.Location;
//import com.squareup.connect.models.Money;
//import com.squareup.connect.models.Money.CurrencyEnum;

public class SquareAPIUtil 
{
//	public static Location getFirstLocation(String token) throws ApiException
//	{
//		ApiClient apiClient = Configuration.getDefaultApiClient();
//
//        // Configure OAuth2 access token for authorization: oauth2
//        OAuth oauth2 = (OAuth) apiClient.getAuthentication("oauth2");
//        oauth2.setAccessToken(token);
//
//        // List all locations
//        LocationsApi locationsApi = new LocationsApi();
//        locationsApi.setApiClient(apiClient);
//
//
//        List<Location> locations = locationsApi.listLocations().getLocations();
//
//        return locations.get(0);
//	}
//
//
//	public static ChargeResponse createCharge(String token, String locationID, ChargeRequest cRequest) throws ApiException
//	{
//		ApiClient defaultClient = Configuration.getDefaultApiClient();
//
//		// Configure OAuth2 access token for authorization: oauth2
//		OAuth oauth2 = (OAuth) defaultClient.getAuthentication("oauth2");
//		oauth2.setAccessToken("YOUR ACCESS TOKEN");
//
//		TransactionsApi apiInstance = new TransactionsApi();
//
//		return apiInstance.charge(locationID, cRequest);
//	}
//
//
//	public static Money amount(CurrencyEnum ce, String value)
//	{
//		return new Money().currency(CurrencyEnum.USD).amount(new BigDecimal(value).multiply(new BigDecimal(100)).longValue());
//	}
}
