import io.xlogistx.opsec.OPSecUtil;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.SecUtil;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.security.Provider;

public class ProviderTest {

    @Test
    public void listProviders() {
        Provider[] providers = SecUtil.getProviders();
        printProviders(providers,false);
        defaultManagers();
        OPSecUtil.singleton();
        defaultManagers();
        providers = SecUtil.getProviders();
        printProviders(providers, false);



    }

    private static void printProviders(Provider[] providers, boolean listProps) {
        System.out.println("Providers count:  " + providers.length);
        for (Provider p : providers) {
            System.err.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            System.out.println(p);
            if (listProps)
                p.list(System.out);
            System.err.println("------------------------------------------------------------------");
        }
    }


    public void defaultManagers() {
        System.out.println("key: "  + KeyManagerFactory.getDefaultAlgorithm());
        System.out.println("trust: " + TrustManagerFactory.getDefaultAlgorithm());
    }
}
