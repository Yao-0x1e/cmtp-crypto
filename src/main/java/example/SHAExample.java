package example;

import crypto.SHAUtils;

import java.util.Arrays;

public class SHAExample {
    public static void main(String[] args) {
        String str = "HelloWorld";
        for (int i = 0; i < 10; i++) {
            byte[] hash = SHAUtils.hash(str);
            System.out.println(Arrays.toString(hash));
        }
    }
}
