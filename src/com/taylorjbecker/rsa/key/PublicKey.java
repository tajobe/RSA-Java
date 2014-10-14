package com.taylorjbecker.rsa.key;

import java.math.BigInteger;

/**
 * Public Key structure
 * 
 * Holds components of RSA public key
 * 
 * n: p x q
 * e: e such that gcd(e, Phi(n)) = 1
 * 
 * @author tajobe
 * 
 */
public class PublicKey
{
    // public key components
    protected BigInteger n;
    private BigInteger e;

    /**
     * Create public key
     * 
     * @param n
     *            p x q portion of pubkey
     * @param e
     *            exponent e so gcd(e, Phi(n)) = 1
     */
    public PublicKey(BigInteger n, BigInteger e)
    {
        this.n = n;
        this.e = e;
    }
    
    /**
     * @return String representation of public key
     */
    public String toString()
    {
        return "(n = " + n.toString() + ", e = " + getE().toString() + ")";
    }

    public BigInteger getE()
    {
        return e;
    }

    public BigInteger getN()
    {
        return n;
    }
}
