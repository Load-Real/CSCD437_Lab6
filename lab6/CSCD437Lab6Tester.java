package lab6;
import java.io.*;
import java.security.*;
import java.util.Scanner;
import javax.crypto.*;

/**
 * This is the main/tester for the class that you are writing. Notice the package statement<br>
 * YOU CAN'T CHANGE ANYTHING IN THIS FILE
 */
public class CSCD437Lab6Tester
{

    /**
     * The main method - tests two different RSA encryption methods
     * @param args - String representing command line arguments
     * @throws Exception for the File processing
     */
    public static void main(final String [] args)throws Exception
    {
        // Alice create public and private keys using the default of SHA256withRSA
        CSCD437Crypto alice = new CSCD437Crypto("SHA256withRSA", "RSA", 1024);

        // Alice publishes the public key
        alice.publishPublicKey("alice.asc");

        // Bob creates public and private keys using a Java defined algorithm
        CSCD437Crypto bob = new CSCD437Crypto("SHA256withRSA", "RSA", 1024);

        // Bob downloads Alice's public key
        PublicKey aliceKey = CSCD437Crypto.getPublicKey("alice.asc");

        // Bob encrypts a message to Alice
        bob.encrypt(aliceKey, "RSA/ECB/PKCS1Padding", "this is a test", "message.enc");

        // Alice decrypts Bob's message using Alice's private key
        alice.decrypt("message.enc", "RSA/ECB/PKCS1Padding");

        System.out.println("\n");



        // Bob is expecting a message in return from Alice so Bob publishes a public key
        bob.publishPublicKey("bob.asc");

        // Alice downloads Bob's public key
        PublicKey bobKey = CSCD437Crypto.getPublicKey("bob.asc");

        // Alice encrypts a message to Bob
        File message = new File("message.txt");
        alice.encrypt(bobKey, "RSA/ECB/PKCS1Padding", message, "toBobMessage.enc");

        // Bob decrypts Alice's message using Bob's private key
        bob.decrypt("toBobMessage.enc", "RSA/ECB/PKCS1Padding");

        System.out.println();

        /**************************************************************************/
        /* Bob needs to send a message to Carol but Carol wants better encryption */
        /**************************************************************************/
        bob.generateKeys("SHA512withRSA", "RSA", 2048);

        CSCD437Crypto carol = new CSCD437Crypto("SHA512withRSA", "RSA", 2048);
        carol.publishPublicKey("carolSHA512.asc");

        // Bob downloads Alice's public key
        PublicKey carolKey = CSCD437Crypto.getPublicKey("carolSHA512.asc");

        // Bob encrypts a message to Alice
        bob.encrypt(carolKey, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "Carol, here is the message you wanted", "carolMessage.enc");

        // Alice decrypts Bob's message using Alice's private key
        carol.decrypt("carolMessage.enc", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

    }// end main

}// end class
