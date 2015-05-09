package fr.beneth.bouncysample;

import java.io.File;
import java.io.IOException;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CTSBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class BouncySample {

    BlockCipher engine = new SerpentEngine();

    public byte[] decrypt(String key2, byte[] iv, byte[] cipherText) {        
        byte[] key = DatatypeConverter.parseHexBinary(key2);
        CTSBlockCipher cipher = new CTSBlockCipher(new CBCBlockCipher(engine));
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] rv = new byte[cipher.getOutputSize(cipherText.length)];
        int tam = cipher.processBytes(cipherText, 0, cipherText.length, rv, 0);
        try {
            cipher.doFinal(rv, tam);
        } catch (Exception ce) {
            ce.printStackTrace();
        }
        return rv;
    }

    public static void main(String[] argv) throws Exception {
        if (argv.length < 3) {
            System.out.println("Usage <file> <IV> <key>");
            System.exit(1);
        }
        
        File f = new File(argv[0]);
        if (! f.exists()) {
            System.out.println(String.format("File %s does not exist", argv[0]));
            System.exit(1);
        }
        System.out.println(String.format("Trying to decrypt file %s with IV %s and  key %s ...",
                argv[0], argv[1], argv[2]));

        BouncySample bs = new BouncySample();

        byte[] fb = FileUtils.readFileToByteArray(f);
        byte[] iv = DatatypeConverter.parseHexBinary(argv[1]);
        
        byte[] outb = bs.decrypt(argv[2], iv, fb);

        FileUtils.writeByteArrayToFile(new File("decrypted"), outb);

        System.out.println("Done.");
    }
}
