package crypto;

import org.bouncycastle.jcajce.provider.digest.SHA256;

import java.nio.charset.StandardCharsets;

public class SHAUtils {
    private static final SHA256.Digest SHA256_DIGEST = new SHA256.Digest();

    public static byte[] hash(String str) {
        return hash(str.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] hash(byte[] bytes) {
        return SHA256_DIGEST.digest(bytes);
    }
}