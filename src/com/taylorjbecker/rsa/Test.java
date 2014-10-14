package com.taylorjbecker.rsa;

import java.math.BigInteger;

/**
 * Basic test class for RSA-Java
 * 
 * @author tajobe
 *
 */
public class Test
{
    public static void main(String[] args)
    {
        System.out.println("Basic test:");
        basicTest();
        System.out.println("\n\nPadded test:");
        paddedTest();
    }
    
    private static void basicTest()
    {
        String sendText = "test"; // plaintext string for Alice to send to Bob
        
        // bob
        RSA Bob = new RSA(64);
        System.out.println("Bob: \n" + Bob.toString() + "\n");
        
        // alice
        RSA Alice = new RSA(64);
        System.out.println("Alice: \n" + Alice.toString() + "\n");
        
        System.out.print("Alice sending \"" + sendText + "\" to Bob...");
        
        // encrypt plaintext
        BigInteger cipher = Alice.encrypt(sendText, Bob.pubKey);
        System.out.println("got ciphertext: " + cipher.toString());
        
        // decrypt ciphertext
        System.out.print("Bob decrypting " + cipher.toString()
                + " from Alice...");
        String plaintext = Bob.decrypt(cipher);
        System.out.println("got plaintext: " + plaintext);
        
        // verify successful encryption/decryption
        System.out
                .println("\nSuccessful encryption/decryption? "
                        + (sendText.equals(plaintext) ? "Yes, decrypted message matches sent."
                                : "No, decrypted message differs from sent."));
    }
    
    private static void paddedTest()
    {
        String sendText = "paddedtest"; // plaintext string for Alice to send to Bob
        
        // bob
        RSA Bob = new RSA(128);
        System.out.println("Bob: \n" + Bob.toString() + "\n");
        
        // alice
        RSA Alice = new RSA(128);
        System.out.println("Alice: \n" + Alice.toString() + "\n");
        
        System.out.print("Alice sending \"" + sendText + "\" to Bob...");
        
        // encrypt plaintext
        BigInteger cipher = Alice.encryptPadded(sendText, Bob.pubKey);
        System.out.println("got ciphertext: " + cipher.toString());
        
        // decrypt ciphertext
        System.out.print("Bob decrypting " + cipher.toString()
                + " from Alice...");
        String plaintext = Bob.decryptPadded(cipher);
        System.out.println("got plaintext: " + plaintext);
        
        // verify successful encryption/decryption
        System.out
                .println("\nSuccessful encryption/decryption? "
                        + (sendText.equals(plaintext) ? "Yes, decrypted message matches sent."
                                : "No, decrypted message differs from sent."));
    }
}
