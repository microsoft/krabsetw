// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using O365.Security.ETW;

namespace EtwTestsCS.Filtering
{
    using Events;

    [TestClass]
    public class describe_Fluent
    {
        // IsInt16
        [TestMethod]
        public void when_int16_values_are_same_is_should_match()
        {
            Int16 data = 5;
            var query = data;
            var record = LogonEvent.CreateRecord(String.Empty, data, 0, 0);
            var predicate = Filter.IsInt16(LogonEvent.KeyLength, query);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void when_int16_values_are_not_same_is_should_not_match()
        {
            Int16 data = 0;
            Int16 query = 1;
            var record = LogonEvent.CreateRecord(String.Empty, data, 0, 0);
            var predicate = Filter.IsInt16(LogonEvent.KeyLength, query);

            Assert.IsFalse(predicate.Test(record));
        }

        // IsInt32
        [TestMethod]
        public void when_int32_values_are_same_is_should_match()
        {
            Int32 data = 5;
            var query = data;
            var record = LogonEvent.CreateRecord(String.Empty, 0, data, 0);
            var predicate = Filter.IsInt32(LogonEvent.LogonType, query);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void when_int32_values_are_not_same_is_should_not_match()
        {
            Int32 data = 0;
            Int32 query = 1;
            var record = LogonEvent.CreateRecord(String.Empty, 0, data, 0);
            var predicate = Filter.IsInt32(LogonEvent.LogonType, query);

            Assert.IsFalse(predicate.Test(record));
        }

        // IsInt64
        [TestMethod]
        public void when_int64_values_are_same_is_should_match()
        {
            Int64 data = 5;
            var query = data;
            var record = LogonEvent.CreateRecord(String.Empty, 0, 0, data);
            var predicate = Filter.IsInt64(LogonEvent.LogonId, query);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void when_int64_values_are_not_same_is_should_not_match()
        {
            Int64 data = 0;
            Int64 query = 1;
            var record = LogonEvent.CreateRecord(String.Empty, 0, 0, data);
            var predicate = Filter.IsInt64(LogonEvent.LogonId, query);

            Assert.IsFalse(predicate.Test(record));
        }
    }
}
