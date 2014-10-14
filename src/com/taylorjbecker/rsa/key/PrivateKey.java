package com.taylorjbecker.rsa.key;

import java.math.BigInteger;

/**
 * Private key structure
 * 
 * Holds components of RDA private key
 * 
 * p: secret prime
 * q: secret prime
 * d: inverse of e in mod Phi(n)
 * 
 * @author tajobe
 * 
 */
public class PrivateKey
{
    // private key components
    private BigInteger p, q, d;

    /**
     * Create private key
     * 
     * @param p
     *            secret prime
     * @param q
     *            secret prime
     * @param d
     *            inverse of e in mod Phi(n)
     */
    public PrivateKey(BigInteger p, BigInteger q, BigInteger d)
    {
        this.p = p;
        this.q = q;
        this.d = d;
    }
    
    /**
     * @return String representation of private key
     */
    public String toString()
    {
        return "(p = " + p.toString() + ", q = " + q.toString() + ", d = " + d.toString() + ")";
    }

    public BigInteger getD()
    {
        return d;
    }
}
