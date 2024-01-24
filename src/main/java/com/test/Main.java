package com.test;
import org.marvec.encryptor.util.EncryptionException;

import com.test.AesEncryption;

public class Main {

    public static void main(String[] args) throws EncryptionException {
        AesEncryption encryption = new AesEncryption();
        encryption.setInitParams();
         String response = encryption.decrypt("65955807CE748F5EFB25B4BD25FD5FD504A958856EDBECFF9E861976685A298D9F2C39C10BA2AE7BBC02893B4856C117");
         System.out.println("response" + response);

        System.out.println(("Hola"));
    }
}