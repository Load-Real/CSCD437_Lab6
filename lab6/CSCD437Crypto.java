package lab6;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Scanner;

public class CSCD437Crypto {
    //Field Summary
    private KeyPairGenerator keyPairGen;
    private KeyPair pair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Signature sign;

    public CSCD437Crypto(String signatureAlgo, String keyPairAlgo, int keySize) {
        try {
            this.sign = Signature.getInstance(signatureAlgo);
            this.keyPairGen = KeyPairGenerator.getInstance(keyPairAlgo);
            this.keyPairGen.initialize(keySize);
            this.pair = this.keyPairGen.generateKeyPair();
            this.publicKey = this.pair.getPublic();
            this.privateKey = this.pair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    //Fundamentally the same as the constructor
    void generateKeys(String signatureAlgo, String keyPairAlgo, int keySize) {
        try {
            this.sign = Signature.getInstance(signatureAlgo);
            this.keyPairGen = KeyPairGenerator.getInstance(keyPairAlgo);
            this.keyPairGen.initialize(keySize);
            this.pair = this.keyPairGen.generateKeyPair();
            this.publicKey = this.pair.getPublic();
            this.privateKey = this.pair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    void publishPublicKey(String filename) {
        try {
            FileOutputStream fileStreamOut = new FileOutputStream(filename);
            ObjectOutputStream objectStreamOut = new ObjectOutputStream(fileStreamOut);
            objectStreamOut.writeObject(this.publicKey);
            fileStreamOut.close();
            objectStreamOut.close();
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    static PublicKey getPublicKey(String filename) {
        try {
            FileInputStream fileStreamIn = new FileInputStream(filename);
            ObjectInputStream objectStreamIn = new ObjectInputStream(fileStreamIn);
            return (PublicKey) objectStreamIn.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    void encrypt(PublicKey publicKey, String transformation, String message, String encryptedFilename) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] arr = message.getBytes(StandardCharsets.UTF_8);
            cipher.update(arr);
            FileOutputStream fileStreamOut = new FileOutputStream(encryptedFilename);
            fileStreamOut.write(cipher.doFinal());
            fileStreamOut.close();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    void encrypt(PublicKey publicKey, String transformation, File messageFile, String encryptedFilename) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            FileInputStream fileStreamIn = new FileInputStream(messageFile);
            byte[] arr = fileStreamIn.readAllBytes();
            cipher.update(arr);
            FileOutputStream fileStreamOut = new FileOutputStream(encryptedFilename);
            fileStreamOut.write(cipher.doFinal());
            fileStreamOut.close();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException |
                 IOException | IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }
    }

    void decrypt(String filename, String transformation) {
        File file = new File(filename);
        try {
            FileInputStream fileStreamIn = new FileInputStream(file);
            byte[] arr = fileStreamIn.readAllBytes();
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
            cipher.update(arr);
            String message = new String(cipher.doFinal());
            System.out.println(message);
        } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}
