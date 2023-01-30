package io.xlogistx.okta;

import io.xlogistx.okta.api.OktaErrorCode;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPResponseData;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class ErrorPageParser
{

    public static OktaErrorCode parseErrorCode(Element e)
    {

        Elements ids = e.getElementsByTag("h4");
        Elements errorCodeMapping = e.select("div[class=\"error-code-mappings\"]");
        Elements errorCodeDescription = e.select("p");//select("div[class=\"error-code-description\"]");
        OktaErrorCode ret = new OktaErrorCode();
        ret.setCodeId(ids.get(0).attr("id"));

        ret.setDescription(errorCodeDescription.html());
        String[] toParse = errorCodeMapping.select("code").html().split(" ");
        ret.setHttpStatus(Integer.parseInt(toParse[0]));

        return ret;

    }

    public static void main(String ...args)
    {
        try
        {

            int index = 0;
            String url = args[index++];
            String filename = args.length > index ? args[index++] : null;
            HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, null, HTTPMethod.GET);
            HTTPResponseData hrd = new HTTPCall(hmci).sendRequest();
            //System.out.println(hrd);
            Document doc = Jsoup.parse(hrd.getDataAsString());
            Elements elements = doc.select("div[class=\"error-code\"]");
            //System.out.println(elements.get(0));

            List<OktaErrorCode> list = new ArrayList<>();
            for(Element e : elements)
            {
                OktaErrorCode oktaErrorCode = parseErrorCode(e);
                list.add(oktaErrorCode);
                //if( HTTPStatusCode.familyByCode(oktaErrorCode.getHttpStatus()) == HTTPStatusCode.Family.CLIENT_ERROR)
                    System.out.println(oktaErrorCode);

            }

            System.out.println(elements.size());

            if(filename != null)
                IOUtil.writeToFile(new File(filename), GSONUtil.toJSONDefault(list, true));
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}
