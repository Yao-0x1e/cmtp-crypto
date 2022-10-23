package test;

import crypto.PEMUtils;

import java.security.PrivateKey;
import java.security.PublicKey;

class PEMUtilsTest {
    private static void doTest(String publicKeyPEM, String privateKeyPEM) throws Exception {
        // 将PEM转换为密钥
        PublicKey publicKey = PEMUtils.convertPEMToPublicKey(publicKeyPEM);
        PrivateKey privateKey = PEMUtils.convertPEMToPrivateKey(privateKeyPEM);
        System.out.println(publicKey);
        System.out.println(privateKey);

        // 将密钥转转为PEM
        publicKeyPEM = PEMUtils.convertPublicKeyToPEM(publicKey);
        privateKeyPEM = PEMUtils.convertPrivateKeyToPEM(privateKey);
        System.out.println(publicKeyPEM);
        System.out.println(privateKeyPEM);
    }

    public static void main(String[] args) throws Exception {
        String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELj/RsTRIKzFIDfkU5bSBejz1Ujdb\n" +
                "j0/DDgnIsyEVFVYhycF5Ue1oEyvpAEGeGypqUPTprwJvewDKgp9Nct3s3w==\n" +
                "-----END PUBLIC KEY-----\n";
        String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4H5dyfvOQACZTQ8j\n" +
                "E/xM+m8aAo1vPssfGF6L9XZ0ki+hRANCAAQuP9GxNEgrMUgN+RTltIF6PPVSN1uP\n" +
                "T8MOCcizIRUVViHJwXlR7WgTK+kAQZ4bKmpQ9OmvAm97AMqCn01y3ezf\n" +
                "-----END PRIVATE KEY-----\n";
        doTest(publicKeyPEM, privateKeyPEM);

        publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4RZ6URM34FPGCT4sjF3UhWpDsFsN\n" +
                "EGs9DqPwzXdv4+GvaNFAGqvyLqzj46glPa7DGci7oRR2g9/TKr99NxBwQQ==\n" +
                "-----END PUBLIC KEY-----\n";
        privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7MbtuXNHp9YQcT5I\n" +
                "OaQqm1kzCSoOwG2lM3V32yboxfmhRANCAAThFnpREzfgU8YJPiyMXdSFakOwWw0Q\n" +
                "az0Oo/DNd2/j4a9o0UAaq/IurOPjqCU9rsMZyLuhFHaD39Mqv303EHBB\n" +
                "-----END PRIVATE KEY-----\n";
        doTest(publicKeyPEM, privateKeyPEM);

        publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEoZTY4MPD/rw5WP1rySs8wPWPJjmTvtCS\n" +
                "IrHAgqw6LRP85tOX3OxD94RprUZpQ2Sdn4ovBswarpmuF6S7EsYc/A==\n" +
                "-----END PUBLIC KEY-----\n";
        privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQguynpsUc7tOb9RIqI5hcw\n" +
                "UMp4vGem0XNkH1ocanmKU4ahRANCAAShlNjgw8P+vDlY/WvJKzzA9Y8mOZO+0JIi\n" +
                "scCCrDotE/zm05fc7EP3hGmtRmlDZJ2fii8GzBquma4XpLsSxhz8\n" +
                "-----END PRIVATE KEY-----\n";
        doTest(publicKeyPEM, privateKeyPEM);

    }
}
