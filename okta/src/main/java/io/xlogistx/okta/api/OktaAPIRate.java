package io.xlogistx.okta.api;

import org.zoxweb.shared.http.HTTPResponse;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.GetValue;

public class OktaAPIRate
implements GetName
{




    public enum LimitHeader
        implements GetValue<String>
    {
        RESET("x-rate-limit-reset"),
        REMAINING("x-rate-limit-remaining"),
        LIMIT("x-rate-limit-limit")

        ;

        private final String headerName;
        LimitHeader(String val)
        {
            headerName = val;
        }
        @Override
        public String getValue() {
            return headerName;
        }
    }


    private int remaining;
    private int limit;
    private long resetInMillis;

    private final String name;


    public OktaAPIRate(String name)
    {
        this.name = name;
    }



    public int getRemaining() {
        return remaining;
    }

    public OktaAPIRate setRemaining(int remaining) {
        this.remaining = remaining;
        return this;
    }

    public int getLimit() {
        return limit;
    }

    public OktaAPIRate setLimit(int limit) {
        this.limit = limit;
        return this;
    }

    public long getResetInMillis() {
        return resetInMillis;
    }

    public OktaAPIRate setResetInMillis(long resetInMillis) {
        this.resetInMillis = resetInMillis;
        return this;
    }

    public OktaAPIRate setResetInSeconds(long resetInSeconds) {
        return setResetInMillis(resetInSeconds*Const.TimeInMillis.SECOND.MILLIS);
    }


    @Override
    public String getName() {
        return name;
    }

    public synchronized OktaAPIRate setParameters(HTTPResponse httpResponse)
    {

        setLimit(httpResponse.intHeaderValue(LimitHeader.LIMIT.getValue()));
        setRemaining(httpResponse.intHeaderValue(LimitHeader.REMAINING.getValue()));
        setResetInSeconds(httpResponse.longHeaderValue(LimitHeader.RESET.getValue()));

        return this;
    }

    @Override
    public String toString() {
        return "OktaAPIRate{" +
                "remaining=" + remaining +
                ", limit=" + limit +
                ", resetInMillis=" + resetInMillis +
                ", name='" + name + '\'' +
                '}';
    }

}
