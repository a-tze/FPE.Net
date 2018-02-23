/**
 * Format-Preserving Encryption
 * 
 * Copyright (c) 2016 Weydstone LLC dba Sutton Abinger
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
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FPE.Net.Test
{

    /// <summary>
    /// Unit test cases for the FF1 class.
    /// 
    /// Original author: Kai Johnson
    /// </summary>
    [TestClass]
    public class FF1Test
    {

        [TestMethod]
        public void testFF1()
        {
            FF1 ff1 = new FF1(10, 0);
            Assert.IsNotNull(ff1);
        }

        [TestMethod]
        public void testEncrypt()
        {
            int radix = 8;
            int maxTlen = 16;

            FF1 ff1 = new FF1(radix, maxTlen);
            Assert.IsNotNull(ff1);

            // set up generic test inputs
            byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
                (byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF, (byte) 0x4F,
                (byte) 0x3C };

            int[] plainText = { 0, 1, 2, 3, 4, 5, 6, 7 };
            byte[] K = key;
            byte[] T = { };
            int[] PT = plainText;

            // null inputs
            try
            {
                K = null;
                PT = plainText;
                ff1.encrypt(K, T, PT);
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }
            try
            {
                K = key;
                T = null;
                PT = plainText;
                ff1.encrypt(K, T, PT);
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }
            try
            {
                K = key;
                T = new byte[0];
                PT = null;
                ff1.encrypt(K, T, PT);
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }

            // wrong key type
            try
            {
                K = new byte[] { 0, 1, 2, 3, 4, 5 };
                T = new byte[0];
                PT = plainText;
                ff1.encrypt(K, T, PT);
            }
            catch (Exception)
            {
            }

            // T is too long
            try
            {
                K = key;
                T = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                PT = plainText;
                ff1.encrypt(K, T, PT);
            }
            catch (Exception)
            {
            }

            // X is too short
            try
            {
                K = key;
                T = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                PT = new int[] { 1 };
                ff1.encrypt(K, T, PT);
            }
            catch (Exception)
            {
            }

            // X is too long
            try
            {
                K = key;
                T = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                PT = new int[Constants.MAXLEN + 1];
                ff1.encrypt(K, T, PT);
            }
            catch (Exception)
            {
            }

            // X is too short for radix
            try
            {
                K = key;
                T = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                PT = new int[] { 1, 2 };
                ff1.encrypt(K, T, PT);
            }
            catch (Exception)
            {
            }

            // d > 16
            radix = 128;
            maxTlen = 16;

            ff1 = new FF1(radix, maxTlen);
            Assert.IsNotNull(ff1);

            K = key;
            T = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            PT = new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                28, 29, 30, 31, 32 };
            int[] CT = ff1.encrypt(K, T, PT);
            CollectionAssert.AreEquivalent(PT, ff1.decrypt(K, T, CT));
        }

        [TestMethod]
        public void testDecrypt()
        {
            int radix = 8;
            int maxTlen = 16;

            FF1 ff1 = new FF1(radix, maxTlen);
            Assert.IsNotNull(ff1);

            // set up generic test inputs
            byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
                (byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF, (byte) 0x4F,
                (byte) 0x3C };

            int[] cipherText = { 0, 1, 2, 3, 4, 5, 6, 7 };
            byte[] K = key;
            byte[] T = { };
            int[] PT = cipherText;

            // null inputs
            try
            {
                K = null;
                T = new byte[] { };
                PT = cipherText;
                ff1.decrypt(K, T, PT);
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }
            try
            {
                K = key;
                T = null;
                PT = cipherText;
                ff1.decrypt(K, T, PT);
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }
            try
            {
                K = key;
                T = new byte[] { };
                PT = null;
                ff1.decrypt(K, T, PT);
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, typeof(NullReferenceException));
            }

            // wrong key type
            try
            {
                K = new byte[] { 0, 1, 2, 3, 4, 5 };
                T = new byte[] { };
                PT = cipherText;
                ff1.decrypt(K, T, PT);
            }
            catch (Exception)
            {
            }

            // T is too long
            try
            {
                K = key;
                T = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                PT = cipherText;
                ff1.decrypt(K, T, PT);
            }
            catch (Exception)
            {
            }

            // X is too short
            try
            {
                K = key;
                T = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                PT = new int[] { 1 };
                ff1.decrypt(K, T, PT);
            }
            catch (Exception)
            {
            }

            // X is too long
            try
            {
                K = key;
                T = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                PT = new int[Constants.MAXLEN + 1];
                ff1.decrypt(K, T, PT);
            }
            catch (Exception)
            {
            }

            // X is too short for radix
            try
            {
                K = key;
                T = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                PT = new int[] { 1, 2 };
                ff1.decrypt(K, T, PT);
            }
            catch (Exception)
            {
            }

            // d > 16
            radix = 128;
            maxTlen = 16;

            ff1 = new FF1(radix, maxTlen);
            Assert.IsNotNull(ff1);

            K = key;
            T = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            int[] CT = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                28, 29, 30, 31, 32 };
            PT = ff1.decrypt(K, T, CT);
            CollectionAssert.AreEquivalent(CT, ff1.encrypt(K, T, PT));
        }

        /// <summary>
        /// Stress test for encrypt() and decrypt() methods
        /// 
        /// This test exercises the encrypt and decrypt methods with inputs of length
        /// 8, 64, 512 and 4096 symbols with each of the permitted key sizes.
        /// </summary>
        [TestMethod]
        public void testStress()
        {
            int[] keySizes = { 128, 192, 256 };

            FF1 ff1 = new FF1(10, 8);

            // for each key size
            foreach (int k in keySizes)
            {
                // generate a new key in the key size
                byte[] K = new byte[k / 8];
                for (int i = 0; i < k / 8; i++)
                {
                    K[i] = (byte)i;
                }

                // init plaintext to a 1 byte array
                int[] PT = { k % 10 };

                // for each plaintext length
                for (int j = 0; j < 4; j++)
                {

                    // make plaintext eight times longer
                    PT = Common.concatenate(PT, PT);
                    PT = Common.concatenate(PT, PT);
                    PT = Common.concatenate(PT, PT);

                    // repeat the test four times
                    for (int i = 0; i < 4; i++)
                    {
                        // create a new tweak array
                        byte[] T = Common.bytestring(i, 8);

                        // encrypt the plaintext
                        int[] CT = ff1.encrypt(K, T, PT);

                        // verify decrypted ciphertext against original plaintext
                        CollectionAssert.AreEquivalent(PT, ff1.decrypt(K, T, CT));

                        // use the ciphertext as the new plaintext
                        PT = CT;
                    }
                }
            }
        }
    }
}