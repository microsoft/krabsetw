using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>
    /// From the EVENT_HEADER.EventProperty defines.
    /// </summary>
    [Flags]
    public enum EventHeaderProperty : ushort
    {
        None = 0,
        XML = 0x0001,
        ForwardedXML = 0x0002,
        LegacyEventLog = 0x0004,
        Relogged = 0x0008
    }

    /// <summary>
    /// Event header access, without needing a schema.
    /// </summary>
    /// <remarks>
    /// Kept as an interface, and kept free of any ref struct in its signature, because
    /// consumers mock it and implement it directly in tests.
    /// </remarks>
    public interface IEventRecordMetadata
    {
        ushort Id { get; }

        byte Opcode { get; }

        byte Version { get; }

        byte Level { get; }

        ushort Flags { get; }

        EventHeaderProperty EventProperty { get; }

        uint ProcessId { get; }

        uint ThreadId { get; }

        DateTime Timestamp { get; }

        Guid ProviderId { get; }

        Guid ActivityId { get; }

        ushort UserDataLength { get; }

        IntPtr UserData { get; }

        /// <summary>
        /// Classifies the event from its header alone, without resolving a schema.
        /// </summary>
        DecodingSource GetEventType();

        /// <summary>Copies the raw payload onto the heap.</summary>
        byte[] CopyUserData();

        bool TryGetContainerId(out Guid result);

        /// <summary>
        /// Available when the session was enabled with EVENT_ENABLE_PROPERTY_PROCESS_START_KEY.
        /// </summary>
        bool TryGetProcessStartKey(out ulong result);
    }

    /// <summary>
    /// A decoded property, used by <see cref="IEventRecord.Properties"/>.
    /// </summary>
    public sealed class Property
    {
        public Property(string name, uint inType, uint outType, uint length)
        {
            Name = name;
            InType = inType;
            OutType = outType;
            Length = length;
        }

        public string Name { get; }

        public uint InType { get; }

        public uint OutType { get; }

        public uint Length { get; }
    }

    /// <summary>
    /// Schema-aware event access.
    /// </summary>
    /// <remarks>
    /// Every accessor here that returns a reference type allocates, which is inherent to the
    /// signature. Callers on a hot path should take <see cref="EventRecordRef"/> instead.
    /// </remarks>
    public interface IEventRecord : IEventRecordMetadata
    {
        string Name { get; }

        string OpcodeName { get; }

        string TaskName { get; }

        string ProviderName { get; }

        DecodingSource DecodingSource { get; }

        IEnumerable<Property> Properties { get; }

        string GetUnicodeString(string name);

        string GetUnicodeString(string name, string defaultValue);

        bool TryGetUnicodeString(string name, [MaybeNullWhen(false)] out string result);

        string GetAnsiString(string name);

        string GetAnsiString(string name, string defaultValue);

        bool TryGetAnsiString(string name, [MaybeNullWhen(false)] out string result);

        string GetCountedString(string name);

        string GetCountedString(string name, string defaultValue);

        bool TryGetCountedString(string name, [MaybeNullWhen(false)] out string result);

        IPAddress GetIPAddress(string name);

        IPAddress GetIPAddress(string name, IPAddress defaultValue);

        bool TryGetIPAddress(string name, [MaybeNullWhen(false)] out IPAddress result);

        SocketAddress GetSocketAddress(string name);

        SocketAddress GetSocketAddress(string name, SocketAddress defaultValue);

        bool TryGetSocketAddress(string name, [MaybeNullWhen(false)] out SocketAddress result);

        /// <remarks>
        /// The C++/CLI implementation used <c>DateTime^</c>, a boxed value type, which C# sees
        /// as <see cref="ValueType"/>. Returning <see cref="DateTime"/> drops that boxing
        /// allocation and is an intentional breaking change. See MIGRATION.md.
        /// </remarks>
        DateTime GetDateTime(string name);

        /// <inheritdoc cref="GetDateTime(string)"/>
        DateTime GetDateTime(string name, DateTime defaultValue);

        /// <inheritdoc cref="GetDateTime(string)"/>
        bool TryGetDateTime(string name, out DateTime result);

        sbyte GetInt8(string name);

        sbyte GetInt8(string name, sbyte defaultValue);

        bool TryGetInt8(string name, out sbyte result);

        byte GetUInt8(string name);

        byte GetUInt8(string name, byte defaultValue);

        bool TryGetUInt8(string name, out byte result);

        short GetInt16(string name);

        short GetInt16(string name, short defaultValue);

        bool TryGetInt16(string name, out short result);

        ushort GetUInt16(string name);

        ushort GetUInt16(string name, ushort defaultValue);

        bool TryGetUInt16(string name, out ushort result);

        int GetInt32(string name);

        int GetInt32(string name, int defaultValue);

        bool TryGetInt32(string name, out int result);

        uint GetUInt32(string name);

        uint GetUInt32(string name, uint defaultValue);

        bool TryGetUInt32(string name, out uint result);

        long GetInt64(string name);

        long GetInt64(string name, long defaultValue);

        bool TryGetInt64(string name, out long result);

        ulong GetUInt64(string name);

        ulong GetUInt64(string name, ulong defaultValue);

        bool TryGetUInt64(string name, out ulong result);

        byte[] GetBinary(string name);

        bool TryGetBinary(string name, [MaybeNullWhen(false)] out byte[] result);

        /// <summary>
        /// Returns the call stack captured with the event, or an empty list when the session
        /// was not enabled with <see cref="TraceFlags.IncludeStackTrace"/>.
        /// </summary>
        List<ulong> GetStackTrace();
    }
}
