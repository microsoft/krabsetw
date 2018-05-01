// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using O365.Security.ETW.Testing;

namespace EtwTestsCS.Events
{
    public static class LogonEvent
    {
        public readonly static string TargetUserName = "TargetUserName";
        public readonly static string KeyLength = "KeyLength";
        public readonly static string LogonType = "LogonType";
        public readonly static string LogonId = "LogonId";

        public readonly static Guid ProviderId = Guid.Parse("199FE037-2B82-40A9-82AC-E1D46C792B99");
        public readonly static int EventId = 301;
        public readonly static int Version = 4;

        public static SynthRecord CreateRecord(
            string username,
            short keyLength,
            int logonType,
            long logonId)
        {
            using (var rb = new RecordBuilder(ProviderId, EventId, Version))
            {
                rb.AddAnsiString(TargetUserName, username);
                rb.AddValue(KeyLength, keyLength);
                rb.AddValue(LogonType, logonType);
                rb.AddValue(LogonId, logonId);

                return rb.PackIncomplete();
            }
        }
    }
}
