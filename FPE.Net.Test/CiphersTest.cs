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
// ReSharper disable ExpressionIsAlwaysNull
// ReSharper disable EmptyGeneralCatchClause

namespace FPE.Net.Test;

/**
 * Unit test cases for the Ciphers class.
 *
 * @author Kai Johnson
 *
 */
[TestFixture]
public class CiphersTest
{

    [Test]
    public void testCiphers()
    {
        Ciphers c = new Ciphers();
        Assert.That(c, Is.Not.Null);
    }

    [Test]
    public void testPrf()
    {
        Ciphers c = new Ciphers();
        Assert.That(c, Is.Not.Null);

        // null inputs
        try
        {
            byte[] K = null;
            byte[] P = [1, 2, 1, 0, 0, 10, 10, 5, 0, 0, 0, 10, 0, 0, 0, 0];
            byte[] Q = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xDD, 0xD5];
            c.prf(K, Common.concatenate(P, Q));
            Assert.Fail();
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }
        try
        {
            byte[] K =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C
            ];
            c.prf(K, null);
            Assert.Fail();
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        // wrong key type
        try
        {
            byte[] K = [0, 0, 0, 0, 0 ,0 ,0];
            byte[] P = [1, 2, 1, 0, 0, 10, 10, 5, 0, 0, 0, 10, 0, 0, 0, 0];
            byte[] Q = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xDD, 0xD5];
            c.prf(K, Common.concatenate(P, Q));
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // X is too short
        try
        {
            byte[] K =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C
            ];
            byte[] X = [];
            c.prf(K, X);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // X is too long
        try
        {
            byte[] K =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C
            ];
            byte[] X = new byte[Constants.MAXLEN + 1];
            c.prf(K, X);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // validation against sample data
        try
        {
            byte[] K =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C
            ];
            byte[] P = [1, 2, 1, 0, 0, 10, 10, 5, 0, 0, 0, 10, 0, 0, 0, 0];
            byte[] Q = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xDD, 0xD5];
            byte[] R =
            [
                0xC3, 0xB8, 41, 0xA1, 0xE8, 100, 43, 120, 0xCC, 41,
                0x94, 123, 59, 0x93, 0xDB, 99
            ];
            Assert.That(R, Is.EquivalentTo(c.prf(K, Common.concatenate(P, Q))));
        }
        catch (Exception)
        {
            Assert.Fail();
        }
    }

    [Test]
    public void testPrf2()
    {
        Ciphers c = new Ciphers();
        Assert.That(c, Is.Not.Null);

        // null inputs
        try
        {
            byte[] K = null;
            byte[] P = [1, 2, 1, 0, 0, 10, 10, 5, 0, 0, 0, 10, 0, 0, 0, 0];
            byte[] Q = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xDD, 0xD5];
            c.prf2(K, Common.concatenate(P, Q));
            Assert.Fail();
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }
        try
        {
            byte[] K =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C
            ];
            c.prf2(K, null);
            Assert.Fail();
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        // wrong key type
        try
        {
            byte[] K = [0, 0, 0, 0, 0, 0, 0];
            byte[] P = [1, 2, 1, 0, 0, 10, 10, 5, 0, 0, 0, 10, 0, 0, 0, 0];
            byte[] Q = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xDD, 0xD5];
            c.prf2(K, Common.concatenate(P, Q));
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // X is too short
        try
        {
            byte[] K =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C
            ];
            byte[] X = [];
            c.prf2(K, X);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // X is too long
        try
        {
            byte[] K =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C
            ];
            byte[] X = new byte[Constants.MAXLEN + 1];
            c.prf2(K, X);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // validation against sample data
        try
        {
            byte[] K =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C
            ];
            byte[] P = [1, 2, 1, 0, 0, 10, 10, 5, 0, 0, 0, 10, 0, 0, 0, 0];
            byte[] Q = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xDD, 0xD5];
            byte[] R =
            [
                0xC3, 0xB8, 41, 0xA1, 0xE8, 100, 43, 120, 0xCC, 41,
                0x94, 123, 59, 0x93, 0xDB, 99
            ];
            Assert.That(R, Is.EquivalentTo(c.prf2(K, Common.concatenate(P, Q))));
        }
        catch (Exception)
        {
            Assert.Fail();
        }
    }

    [Test]
    public void testCiph()
    {
        Ciphers c = new Ciphers();
        Assert.That(c, Is.Not.Null);

        // null inputs
        try
        {
            byte[] X = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            c.ciph(null, X);
            Assert.Fail();
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }
        try
        {
            byte[] K = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            c.ciph(K, null);
            Assert.Fail();
        }
        catch (Exception e)
        {
            Assert.That(e, Is.InstanceOf<NullReferenceException>());
        }

        // wrong key type
        try
        {
            byte[] K = [0, 1, 2, 3, 4, 5, 6];
            byte[] X = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            c.ciph(K, X);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // X is too short
        try
        {
            byte[] K = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            byte[] X = [];
            c.ciph(K, X);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // X is too long
        try
        {
            byte[] K = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            byte[] X = new byte[Constants.MAXLEN + 1];
            c.ciph(K, X);
            Assert.Fail();
        }
        catch (Exception)
        {
        }

        // NIST AES Core 128 sample 1
        try
        {
            byte[] K =
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2,
                0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C
            ];
            byte[] X =
            [
                0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F,
                0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
                0x17, 0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E,
                0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC,
                0x45, 0xAF, 0x8E, 0x51, 0x30, 0xC8, 0x1C,
                0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB,
                0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF, 0xF6,
                0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
                0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37,
                0x10
            ];
            byte[] Y =
            [
                0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36,
                0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66,
                0xEF, 0x97, 0xF5, 0xD3, 0xD5, 0x85, 0x03,
                0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A,
                0x96, 0xFD, 0xBA, 0xAF, 0x43, 0xB1, 0xCD,
                0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B,
                0x00, 0xE3, 0xED, 0x03, 0x06, 0x88, 0x7B,
                0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F,
                0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D,
                0xD4
            ];
            Assert.That(Y, Is.EquivalentTo(c.ciph(K, X)));
        }
        catch (Exception)
        {
            Assert.Fail();
        }
    }
}
