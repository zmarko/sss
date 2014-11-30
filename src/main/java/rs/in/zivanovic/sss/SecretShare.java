/*
 * The MIT License
 *
 * Copyright 2014 Marko Zivanovic.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package rs.in.zivanovic.sss;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Value class containing data necessary to fully describe single secret share in the series.
 */
public final class SecretShare {

    private final int n;
    private final BigInteger share;
    private final BigInteger prime;

    /**
     * Construct secret share object with the specified data.
     *
     * @param n ordinal number of this specific share in the series
     * @param share specific share data
     * @param prime prime number used for the series
     */
    public SecretShare(int n, BigInteger share, BigInteger prime) {
        this.n = n;
        this.share = share;
        this.prime = prime;
    }

    public int getN() {
        return n;
    }

    public BigInteger getShare() {
        return share;
    }

    public BigInteger getPrime() {
        return prime;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 79 * hash + this.n;
        hash = 79 * hash + Objects.hashCode(this.share);
        hash = 79 * hash + Objects.hashCode(this.prime);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SecretShare other = (SecretShare) obj;
        if (this.n != other.n) {
            return false;
        }
        if (!Objects.equals(this.share, other.share)) {
            return false;
        }
        if (!Objects.equals(this.prime, other.prime)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "SecretShare{" + "n=" + n + ", share=" + share + ", prime=" + prime + '}';
    }

}
