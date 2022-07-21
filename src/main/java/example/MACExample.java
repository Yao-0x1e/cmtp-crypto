package example;

import crypto.MACUtils;

import java.util.Arrays;

public class MACExample {
    public static void main(String[] args) throws Exception {
        String str = "HelloWorld";
        byte[] key = "TestKey".getBytes();
        for (int i = 0; i < 10; i++) {
            byte[] mac = MACUtils.mac(str, key);
            System.out.println(Arrays.toString(mac));
        }
    }
}
