/*
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
using NUnit.Framework;

// ReSharper disable RedundantAssignment

// ReSharper disable ExpressionIsAlwaysNull
// ReSharper disable EmptyGeneralCatchClause

namespace FPE.Net.Test;

/// <summary>
/// Unit test cases for the FF1 class.
///
/// Original author: Kai Johnson
/// </summary>
[TestFixture]
public class Ff1Test
{
    [Test]
    public void testFf1()
    {
        FF1 ff1 = new FF1(10, 0);
        Assert.That(ff1, Is.Not.Null);
    }

    [Test]
    public void testEncrypt()
    {
        int radix = 8;
        int maxTlen = 16;

        FF1 ff1 = new FF1(radix, maxTlen);
        Assert.That(ff1, Is.Not.Null);

        // set up generic test inputs
        byte[] key =
        [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
            0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
            0x3C
        ];

        int[] plainText = [0, 1, 2, 3, 4, 5, 6, 7];
        byte[] K = key;
        byte[] T = [];
        int[] pt = plainText;

        // null inputs
        try
        {
            K = null;
            pt = plainText;
            ff1.encrypt(K, T, pt);
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        try
        {
            K = key;
            T = null;
            pt = plainText;
            ff1.encrypt(K, T, pt);
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        try
        {
            K = key;
            T = [];
            pt = null;
            ff1.encrypt(K, T, pt);
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        // wrong key type
        try
        {
            K = [0, 1, 2, 3, 4, 5];
            T = [];
            pt = plainText;
            ff1.encrypt(K, T, pt);
        }
        catch (Exception)
        {
        }

        // T is too long
        try
        {
            K = key;
            T = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            pt = plainText;
            ff1.encrypt(K, T, pt);
        }
        catch (Exception)
        {
        }

        // X is too short
        try
        {
            K = key;
            T = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            pt = [1];
            ff1.encrypt(K, T, pt);
        }
        catch (Exception)
        {
        }

        // X is too long
        try
        {
            K = key;
            T = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            pt = new int[Constants.MAXLEN + 1];
            ff1.encrypt(K, T, pt);
        }
        catch (Exception)
        {
        }

        // X is too short for radix
        try
        {
            K = key;
            T = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            pt = [1, 2];
            ff1.encrypt(K, T, pt);
        }
        catch (Exception)
        {
        }

        // d > 16
        radix = 128;
        maxTlen = 16;

        ff1 = new FF1(radix, maxTlen);
        Assert.That(ff1, Is.Not.Null);

        K = key;
        T = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        pt =
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
            28, 29, 30, 31, 32
        ];
        int[] ct = ff1.encrypt(K, T, pt);
        Assert.That(pt, Is.EquivalentTo(ff1.decrypt(K, T, ct)));
    }

    [Test]
    public void testDecrypt()
    {
        int radix = 8;
        int maxTlen = 16;

        FF1 ff1 = new FF1(radix, maxTlen);
        Assert.That(ff1, Is.Not.Null);

        // set up generic test inputs
        byte[] key =
        [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
            0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
            0x3C
        ];

        int[] cipherText = [0, 1, 2, 3, 4, 5, 6, 7];
        byte[] K = key;
        byte[] T = [];
        int[] pt = cipherText;

        // null inputs
        try
        {
            K = null;
            T = [];
            pt = cipherText;
            ff1.decrypt(K, T, pt);
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        try
        {
            K = key;
            T = null;
            pt = cipherText;
            ff1.decrypt(K, T, pt);
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        try
        {
            K = key;
            T = [];
            pt = null;
            ff1.decrypt(K, T, pt);
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        // wrong key type
        try
        {
            K = [0, 1, 2, 3, 4, 5];
            T = [];
            pt = cipherText;
            ff1.decrypt(K, T, pt);
        }
        catch (Exception)
        {
        }

        // T is too long
        try
        {
            K = key;
            T = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            pt = cipherText;
            ff1.decrypt(K, T, pt);
        }
        catch (Exception)
        {
        }

        // X is too short
        try
        {
            K = key;
            T = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            pt = [1];
            ff1.decrypt(K, T, pt);
        }
        catch (Exception)
        {
        }

        // X is too long
        try
        {
            K = key;
            T = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            pt = new int[Constants.MAXLEN + 1];
            ff1.decrypt(K, T, pt);
        }
        catch (Exception)
        {
        }

        // X is too short for radix
        try
        {
            K = key;
            T = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            pt = [1, 2];
            ff1.decrypt(K, T, pt);
        }
        catch (Exception)
        {
        }

        // d > 16
        radix = 128;
        maxTlen = 16;

        ff1 = new FF1(radix, maxTlen);
        Assert.That(ff1, Is.Not.Null);

        K = key;
        T = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        int[] ct =
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
            28, 29, 30, 31, 32
        ];
        pt = ff1.decrypt(K, T, ct);
        Assert.That(ct, Is.EquivalentTo(ff1.encrypt(K, T, pt)));
    }

    /// <summary>
    /// Stress test for encrypt() and decrypt() methods
    ///
    /// This test exercises the encrypt and decrypt methods with inputs of length
    /// 8, 64, 512 and 4096 symbols with each of the permitted key sizes.
    /// </summary>
    [Test]
    public void testStress()
    {
        int[] keySizes = [128, 192, 256];

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
            int[] pt = [k % 10];

            // for each plaintext length
            for (int j = 0; j < 4; j++)
            {
                // make plaintext eight times longer
                pt = Common.concatenate(pt, pt);
                pt = Common.concatenate(pt, pt);
                pt = Common.concatenate(pt, pt);

                // repeat the test four times
                for (int i = 0; i < 4; i++)
                {
                    // create a new tweak array
                    byte[] T = Common.bytestring(i, 8);

                    // encrypt the plaintext
                    int[] ct = ff1.encrypt(K, T, pt);

                    // verify decrypted ciphertext against original plaintext
                    Assert.That(pt, Is.EquivalentTo(ff1.decrypt(K, T, ct)));

                    // use the ciphertext as the new plaintext
                    pt = ct;
                }
            }
        }
    }
}
