using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Numerics;

namespace FPE.Net.Test
{

    /**
     * JUnit test cases for the Constants class
     * 
     * @author Kai Johnson
     *
     */
    [TestClass]
    public class ConstantsTest {

        [TestMethod]
        public void testConstants() {
            // validate values of MINLEN and MAXLEN
            Assert.IsTrue(Constants.MINLEN >= 2);
            Assert.IsTrue(Constants.MINLEN <= Constants.MAXLEN);
            Assert.IsTrue(Constants.MAXLEN <= Math.Pow(2, 32));

            // validate values of MINRADIX and MAXRADIX
            Assert.IsTrue(Constants.MINRADIX >= 2);
            Assert.IsTrue(Constants.MINRADIX <= Constants.MAXRADIX);
            Assert.IsTrue(Constants.MAXRADIX <= Math.Pow(2, 16));

        }

    }
}