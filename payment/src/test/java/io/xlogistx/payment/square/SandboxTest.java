package io.xlogistx.payment.square;


//import com.squareup.connect.models.ChargeRequest;
//import com.squareup.connect.models.Location;
//import com.squareup.connect.models.Money;
//import com.squareup.connect.models.Money.CurrencyEnum;

public class SandboxTest 
{

	
	
	
	public static void main(String[] args) 
	{
    
		
		try
		{
			int index = 0;
			String token = args[index++];
			
			
			
//			Money amount = SquareAPIUtil.amount(CurrencyEnum.USD, args[index++]);
//			System.out.println(amount);
//
//
//
////			ApiClient apiClient = Configuration.getDefaultApiClient();
////
////	        // Configure OAuth2 access token for authorization: oauth2
////	        OAuth oauth2 = (OAuth) apiClient.getAuthentication("oauth2");
////	        oauth2.setAccessToken(token);
////
////	        // List all locations
////	        LocationsApi locationsApi = new LocationsApi();
////	        locationsApi.setApiClient(apiClient);
////
////	        try {
////	            List<Location> locations = locationsApi.listLocations().getLocations();
////	            System.out.println(locations);
////	        } catch (ApiException e) {
////	            System.err.println("Exception when calling API");
////	            e.printStackTrace();
////	        }
//
//			Location location = SquareAPIUtil.getFirstLocation(token);
//			System.out.println(location);
//			ChargeRequest cr = new ChargeRequest();
//			cr.amountMoney(amount);
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
    }
}
