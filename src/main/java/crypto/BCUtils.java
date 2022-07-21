package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class BCUtils {
    public static void addBCProviderIfNull() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
