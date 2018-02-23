/**
 * Format-Preserving Encryption
 * 
 * Copyright (c) 2016 Weydstone LLC dba Sutton Abinger
 * Copyright (c) 2018 Matthias Hunstock (ported to .NET)
 * 
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership. Sutton Abinger licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
using System;
using System.Security.Cryptography;

namespace FPE.Net
{
    /**
     * Common cipher functions for FF1 and FF3 based on AES.
     * 
     * @author Kai Johnson
     *
     */
    internal class Ciphers
    {

        /**
         * Instance of the AES cipher in ECB mode with no padding.
         */
        private AesManaged mAesEcbCipher;

        /**
         * Instance of the AES cipher in CBC mode with no padding.
         */
        private AesManaged mAesCbcCipher;

        /**
         * Constructs a Ciphers instance with the required AES ciphers.
         */
        public Ciphers()
        {
            try
            {
                mAesEcbCipher = new AesManaged() {
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None,
                    KeySize = 128
                };

                mAesCbcCipher = new AesManaged()
                {
                    Mode = CipherMode.CBC,
                    Padding = PaddingMode.None,
                    KeySize = 128
                };
            }
            catch (Exception e)
            {
                // this would be a programming error so convert to an unchecked
                // exception
                throw e;
            }
        }

        /**
         * NIST SP 800-38G Algorithm 6: PRF(X) - Applies the pseudorandom function
         * to the input using the supplied key.
         * <p>
         * Prerequisites:<br>
         * Designated cipher function, CIPH, of an approved 128-bit block
         * cipher;<br>
         * Key, K, for the block cipher.
         * <p>
         * Input:<br>
         * Block string, X.
         * <p>
         * Output:<br>
         * Block, Y.
         * 
         * @param K
         *            The AES key for the cipher function.
         * @param X
         *            The block string input.
         * @return The output of the function PRF applied to the block X; PRF is
         *         defined in terms of a given designated cipher function.
         * @throws Exception
         *             If the key is not a valid AES key.
         */
        public byte[] prf(byte[] K, byte[] X)
        {
            // validate K
            if (K == null)
                throw new NullReferenceException("K must not be null");

            // validate X
            if (X == null)
                throw new NullReferenceException("X must not be null");
            if (X.Length < 1 || X.Length > Constants.MAXLEN)
                throw new Exception(
                    "The length of X is not within the permitted range of 1.." + Constants.MAXLEN + ": " + X.Length);

            // 1. Let m = LEN(X)/128.
            // i.e. BYTELEN(X)/16
            int m = X.Length / 16;

            // 2. Let X[1], ï¿½, X[m] be the blocks for which X = X[1] || ï¿½ || X[m].
            // we extract the blocks inside the for loop

            // 3. Let Y(0) = bitstring(0,128), and
            byte[] Y = Common.bitstring(false, 128);

            // for j from 1 to m let Y(j) = CIPH(K,Y(jï¿½1) xor X[j]).
            for (int j = 0; j < m; j++)
            {
                // quelle, from, to
                byte[] Xj = new byte[16];
                Array.Copy(X, j * 16, Xj, 0, 16);
                try
                {
                    mAesEcbCipher.Key = K;
                    var enc = mAesEcbCipher.CreateEncryptor();
                    //mAesEcbCipher.init(Cipher.ENCRYPT_MODE, K);
                    var temp = Common.xor(Y, Xj);
                    //Y = mAesEcbCipher.doFinal(Common.xor(Y, Xj));
                    Y = enc.TransformFinalBlock(temp, 0, temp.Length);

                }
                catch (Exception e)
                {
                    // these would be programming errors so convert to an unchecked
                    // exception
                    throw e;
                }
            }

            // 4. Return Y(m).
            return Y;
        }

        /**
         * Equivalent implementation of the PRF(X) algorithm using the AES CBC
         * cipher with a zero initialization vector.
         * <p>
         * The PRF(X) algorithm is an implementation of CBC mode encryption with a
         * zero initialization vector. PRF(X) then extracts the last block as the
         * result. Instead of implementing CBC by hand, this method uses the Java
         * libraries to perform the same operation, and to demonstrate the
         * equivalence of the methods.
         * 
         * @param K
         *            The AES key for the cipher function
         * @param X
         *            The block string input
         * @return The output of the function PRF applied to the block X; PRF is
         *         defined in terms of a given designated cipher function.
         * @throws Exception
         *             If the key is not a valid AES key.
         */
        public byte[] prf2(byte[] K, byte[] X)
        {
            // validate K
            if (K == null)
                throw new NullReferenceException("K must not be null");

            // validate X
            if (X == null)
                throw new NullReferenceException("X must not be null");
            if (X.Length < 1 || X.Length > Constants.MAXLEN)
                throw new Exception(
                        "The length of X is not within the permitted range of 1.." + Constants.MAXLEN + ": " + X.Length);

            byte[] Z;

            try
            {
                byte[] Y = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00 };

                var enc = mAesCbcCipher.CreateEncryptor(K, Y);
                //mAesCbcCipher.init(Cipher.ENCRYPT_MODE, K, new IvParameterSpec(Y));

                //Z = mAesCbcCipher.doFinal(X);
                Z = enc.TransformFinalBlock(X, 0, X.Length);
            }
            catch (Exception e)
            {
                // these would be programming errors so convert to an unchecked
                // exception
                throw e;
            }
            byte[] ret = new byte[16];
            Array.Copy(Z, Z.Length - 16, ret, 0, 16);
            return ret;
        }

        /**
         * Encrypts the input using the AES block cipher in ECB mode using the
         * specified key.
         * <p>
         * Although the ECB mode of operation is not explicitly mentioned in NIST SP
         * 800-38G, it is implied by the use of the CIPH(X) function in FF1 and FF3.
         * <p>
         * To quote NIST SP 800-38G, "For both of the modes, the underlying block
         * cipher shall be approved, and the block size shall be 128 bits.
         * Currently, the AES block cipher, with key lengths of 128, 192, or 256
         * bits, is the only block cipher that fits this profile."
         * 
         * @param K
         *            The AES key for the cipher function
         * @param X
         *            The block string input
         * @return The output of the cipher function applied to the block X.
         * @throws Exception
         *             If the key is not a valid AES key.
         */
        public byte[] ciph(byte[] K, byte[] X)
        {
            // validate K
            if (K == null)
                throw new NullReferenceException("K must not be null");

            // validate X
            if (X == null)
                throw new NullReferenceException("X must not be null");
            if (X.Length < 1 || X.Length > Constants.MAXLEN)
                throw new Exception(
                        "The length of X is not within the permitted range of 1.." + Constants.MAXLEN + ": " + X.Length);

            byte[] cipherText;
            try
            {
                mAesEcbCipher.Key = K;
                var enc = mAesEcbCipher.CreateEncryptor();
                //mAesEcbCipher.init(Cipher.ENCRYPT_MODE, K);

                //cipherText = mAesEcbCipher.doFinal(X);
                cipherText = enc.TransformFinalBlock(X, 0, X.Length);

            }
            catch (Exception e)
            {
                // these would be programming errors so convert to an unchecked
                // exception
                throw e;
            }

            return cipherText;
        }
    }
}
