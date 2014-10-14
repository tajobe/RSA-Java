package com.taylorjbecker.rsa;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import com.taylorjbecker.rsa.key.PrivateKey;
import com.taylorjbecker.rsa.key.PublicKey;

/**
 * Simple RSA implementation
 * 
 * @author tajobe
 * 
 */
public class RSA
{
    // secure random generator(self-seeding)
    private static final SecureRandom RANDOM = new SecureRandom();
    
    // keypair
    public PublicKey pubKey;
    private PrivateKey privKey;
    
    /**
     * Generate RSA keys n = p x q length of roughly N
     * 
     * @param N
     *            bit length of n to generate
     */
    public RSA(int N)
    {
        // generate p and q
        BigInteger p = BigInteger.probablePrime(N / 2, RANDOM);
        BigInteger q = BigInteger.probablePrime(N / 2, RANDOM);
        
        // n = p x q
        BigInteger n = p.multiply(q);
        
        // calculate Phi(n)
        BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        
        // find e with gcd(e, Phi(n)) = 1
        BigInteger e;
        do
        {
            e = new BigInteger(N, RANDOM);
        } while (e.gcd(phiN).compareTo(BigInteger.ONE) != 0 || // gcd(e, Phi(n)) != 1
                e.compareTo(phiN) == 1); // 1 < e < Phi(N)(This checks if e > Phi(N))
        
        // calculate d
        BigInteger d = e.modInverse(phiN);
        
        // create keys with generate values
        pubKey = new PublicKey(n, e);
        privKey = new PrivateKey(p, q, d);
    }
    
    /**
     * Encrypt message plaintext
     * 
     * @param plaintext
     *            text to encrypt
     * @param to
     *            public key of user we are sending message to
     * @return ciphertext(encrypted message)
     */
    public BigInteger encrypt(String plaintext, PublicKey to)
    {
        return (new BigInteger(plaintext.getBytes())).modPow(to.getE(), to.getN());
    }
    
    /**
     * Encrypt message plaintext with padding
     *
     * @param plaintext
     *            text to encrypt
     * @param to
     *            public key of user we are sending message to
     * @return ciphertext(encrypted message)
     */
    public BigInteger encryptPadded(String plaintext, PublicKey to)
    {
        byte[] m = plaintext.getBytes();

        // pad message to size of key
        byte[] padded = new byte[to.getN().toByteArray().length - 1];

        // need last 2 bytes for pad count so strings must be shorter than that
        if (m.length > padded.length - 2)
            throw new IllegalArgumentException("Message too long!");

        // copy message into padded array
        System.arraycopy(m, 0, padded, 0, m.length);

        // save size of pad in last 2 bytes(short)
        byte[] numPadded = ByteBuffer.allocate(2)
                .putShort((short) (padded.length - m.length)).array();
        System.arraycopy(numPadded, 0, padded, padded.length
                - numPadded.length, numPadded.length);

        return (new BigInteger(padded)).modPow(to.getE(), to.getN());
    }

    
    /**
     * Decrypt message sent to us
     * 
     * @param ciphertext
     *            text to decrypt
     * @return plaintext message
     */
    public String decrypt(BigInteger ciphertext)
    {
        return new String(ciphertext.modPow(privKey.getD(), pubKey.getN()).toByteArray());
    }
    
    /**
     * Decrypt padded message sent to us
     *
     * @param ciphertext
     *            text to decrypt
     * @return plaintext message
     */
    public String decryptPadded(BigInteger ciphertext)
    {
        byte[] padded = ciphertext.modPow(privKey.getD(), pubKey.getN()).toByteArray();
        short numPad = ByteBuffer.wrap(
                Arrays.copyOfRange(padded, padded.length - 2, padded.length))
                .getShort();

        return new String(Arrays.copyOfRange(padded, 0, padded.length - numPad));
    }
    
    /**
     * @return String representation of this RSA instance
     */
    public String toString()
    {
        return "Public key: " + pubKey.toString() + "\nPrivate key: "
                + privKey.toString();
    }
}
