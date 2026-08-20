using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>
    /// Presents an event through <see cref="IEventRecord"/>.
    /// </summary>
    /// <remarks>
    /// One instance per trace, reused for every event, matching what the C++/CLI wrapper does.
    /// Reuse is safe only because a trace delivers events on one thread and the instance is
    /// invalidated when the callback returns; a caller that stashes the reference and reads it
    /// later gets an exception rather than data from an unrelated event or freed memory.
    /// </remarks>
    internal sealed unsafe class EventRecordAdapter : IEventRecord
    {
        /// <summary>
        /// The largest FILETIME <see cref="DateTime.FromFileTimeUtc"/> accepts:
        /// <see cref="DateTime.MaxValue"/> expressed as ticks since 1601-01-01. Anything
        /// above it throws rather than returning a time.
        /// </summary>
        private const long MaxRepresentableFileTime = 2650467743999999999;

        private EVENT_RECORD* _record;
        private EventScratch _scratch = null!;

        public void Begin(EVENT_RECORD* record, EventScratch scratch)
        {
            _record = record;
            _scratch = scratch;
        }

        public void End()
        {
            _record = null;
        }

        /// <summary>
        /// The record, or a diagnostic if it is no longer valid.
        /// </summary>
        /// <remarks>
        /// Every accessor goes through this, including the extended-data ones. Reading
        /// <c>_record</c> directly would make a stale read *quietly* return "no container id"
        /// or an empty stack rather than failing, and a consumer cannot tell that apart from
        /// an event that genuinely carried neither.
        /// <para>
        /// The throw lives in its own method so that this one stays a null check the JIT will
        /// inline. Inline, the string concatenation alone puts it past the inlining budget,
        /// and every header read then costs two calls instead of a compare.
        /// </para>
        /// </remarks>
        private EVENT_RECORD* ValidRecord
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get
            {
                if (_record == null)
                {
                    ThrowInvalidated();
                }

                return _record;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void ThrowInvalidated()
        {
            throw new InvalidOperationException(
                "This event record is no longer valid. It points at a buffer owned by ETW " +
                "that is only live for the duration of the callback. Copy what you need " +
                "before returning, or use EventRecordRef.");
        }

        private EventRecordRef Ref
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return new EventRecordRef(ValidRecord, _scratch); }
        }

        #region Metadata

        public ushort Id
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return Ref.Id; }
        }

        public byte Opcode
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return Ref.Opcode; }
        }

        public byte Version
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return Ref.Version; }
        }

        public byte Level
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return Ref.Level; }
        }

        public ushort Flags
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return Ref.Flags; }
        }

        public EventHeaderProperty EventProperty
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return (EventHeaderProperty)Ref.EventProperty; }
        }

        public uint ProcessId
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return Ref.ProcessId; }
        }

        public uint ThreadId
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return Ref.ThreadId; }
        }

        public DateTime Timestamp => Ref.Timestamp;

        public Guid ProviderId
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return Ref.ProviderId; }
        }

        public Guid ActivityId
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return Ref.ActivityId; }
        }

        public ushort UserDataLength
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return Ref.UserDataLength; }
        }

        public IntPtr UserData
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return Ref.UserData; }
        }

        public DecodingSource GetEventType()
        {
            return Ref.GetEventType();
        }

        public List<ulong> GetStackTrace()
        {
            return ExtendedData.GetStackTrace(ValidRecord);
        }

        public byte[] CopyUserData()
        {
            return Ref.UserDataSpan.ToArray();
        }

        public bool TryGetContainerId(out Guid result)
        {
            return ExtendedData.TryGetContainerId(ValidRecord, out result);
        }

        public bool TryGetProcessStartKey(out ulong result)
        {
            return ExtendedData.TryGetProcessStartKey(ValidRecord, out result);
        }

        #endregion

        #region Schema

        public string Name => Ref.Name.ToString();

        public string OpcodeName => Ref.OpcodeName.ToString();

        public string TaskName => Ref.TaskName.ToString();

        public string ProviderName => Ref.ProviderName.ToString();

        public DecodingSource DecodingSource => Ref.DecodingSource;

        public IEnumerable<Property> Properties
        {
            get
            {
                var record = Ref;
                int count = record.PropertyCount;
                var result = new List<Property>(count);

                for (int i = 0; i < count; i++)
                {
                    result.Add(new Property(
                        record.PropertyNameAt(i).ToString(),
                        record.InTypeAt(i),
                        record.OutTypeAt(i),
                        record.TryGetRaw(i, out ReadOnlySpan<byte> raw) ? (uint)raw.Length : 0u));
                }

                return result;
            }
        }

        #endregion

        #region Strings

        public string GetUnicodeString(string name)
        {
            return TryGetUnicodeString(name, out string? result) ? result : throw Missing(name);
        }

        public string GetUnicodeString(string name, string defaultValue)
        {
            return TryGetUnicodeString(name, out string? result) ? result : defaultValue;
        }

        public bool TryGetUnicodeString(string name, [MaybeNullWhen(false)] out string result)
        {
            if (Ref.TryGetUnicodeString(name.AsSpan(), out ReadOnlySpan<char> value))
            {
                result = value.ToString();
                return true;
            }

            result = null;
            return false;
        }

        public string GetCountedString(string name)
        {
            return TryGetCountedString(name, out string? result) ? result : throw Missing(name);
        }

        public string GetCountedString(string name, string defaultValue)
        {
            return TryGetCountedString(name, out string? result) ? result : defaultValue;
        }

        public bool TryGetCountedString(string name, [MaybeNullWhen(false)] out string result)
        {
            if (Ref.TryGetCountedString(name.AsSpan(), out ReadOnlySpan<char> value))
            {
                result = value.ToString();
                return true;
            }

            result = null;
            return false;
        }

        public string GetAnsiString(string name)
        {
            return TryGetAnsiString(name, out string? result) ? result : throw Missing(name);
        }

        public string GetAnsiString(string name, string defaultValue)
        {
            return TryGetAnsiString(name, out string? result) ? result : defaultValue;
        }

        public bool TryGetAnsiString(string name, [MaybeNullWhen(false)] out string result)
        {
            if (Ref.TryGetAnsiStringBytes(name.AsSpan(), out ReadOnlySpan<byte> value, out ushort outType))
            {
                result = value.Length == 0 ? string.Empty : Decode(value, outType);
                return true;
            }

            result = null;
            return false;
        }

        /// <summary>
        /// An 8-bit string property carries the provider's ANSI code page unless its out-type
        /// says otherwise -- see <see cref="Interop.AnsiEncoding"/> for the citation, the
        /// out-types that mean UTF-8, and the provider survey.
        /// </summary>
        private static string Decode(ReadOnlySpan<byte> value, ushort outType)
        {
            fixed (byte* p = value)
            {
                return Interop.AnsiEncoding.ForOutType(outType).GetString(p, value.Length);
            }
        }

        #endregion

        #region Numbers

        public sbyte GetInt8(string name) => TryGetInt8(name, out sbyte v) ? v : throw Missing(name);

        public sbyte GetInt8(string name, sbyte defaultValue) => TryGetInt8(name, out sbyte v) ? v : defaultValue;

        public bool TryGetInt8(string name, out sbyte result) => Ref.TryGetInt8(name.AsSpan(), out result);

        public byte GetUInt8(string name) => TryGetUInt8(name, out byte v) ? v : throw Missing(name);

        public byte GetUInt8(string name, byte defaultValue) => TryGetUInt8(name, out byte v) ? v : defaultValue;

        public bool TryGetUInt8(string name, out byte result) => Ref.TryGetUInt8(name.AsSpan(), out result);

        public short GetInt16(string name) => TryGetInt16(name, out short v) ? v : throw Missing(name);

        public short GetInt16(string name, short defaultValue) => TryGetInt16(name, out short v) ? v : defaultValue;

        public bool TryGetInt16(string name, out short result) => Ref.TryGetInt16(name.AsSpan(), out result);

        public ushort GetUInt16(string name) => TryGetUInt16(name, out ushort v) ? v : throw Missing(name);

        public ushort GetUInt16(string name, ushort defaultValue) => TryGetUInt16(name, out ushort v) ? v : defaultValue;

        public bool TryGetUInt16(string name, out ushort result) => Ref.TryGetUInt16(name.AsSpan(), out result);

        public int GetInt32(string name) => TryGetInt32(name, out int v) ? v : throw Missing(name);

        public int GetInt32(string name, int defaultValue) => TryGetInt32(name, out int v) ? v : defaultValue;

        public bool TryGetInt32(string name, out int result) => Ref.TryGetInt32(name.AsSpan(), out result);

        public uint GetUInt32(string name) => TryGetUInt32(name, out uint v) ? v : throw Missing(name);

        public uint GetUInt32(string name, uint defaultValue) => TryGetUInt32(name, out uint v) ? v : defaultValue;

        public bool TryGetUInt32(string name, out uint result) => Ref.TryGetUInt32(name.AsSpan(), out result);

        public long GetInt64(string name) => TryGetInt64(name, out long v) ? v : throw Missing(name);

        public long GetInt64(string name, long defaultValue) => TryGetInt64(name, out long v) ? v : defaultValue;

        public bool TryGetInt64(string name, out long result) => Ref.TryGetInt64(name.AsSpan(), out result);

        public ulong GetUInt64(string name) => TryGetUInt64(name, out ulong v) ? v : throw Missing(name);

        public ulong GetUInt64(string name, ulong defaultValue) => TryGetUInt64(name, out ulong v) ? v : defaultValue;

        public bool TryGetUInt64(string name, out ulong result) => Ref.TryGetUInt64(name.AsSpan(), out result);

        #endregion

        #region Structured

        public byte[] GetBinary(string name)
        {
            return TryGetBinary(name, out byte[]? result) ? result : throw Missing(name);
        }

        public bool TryGetBinary(string name, [MaybeNullWhen(false)] out byte[] result)
        {
            if (Ref.TryGetBinary(name.AsSpan(), out ReadOnlySpan<byte> value))
            {
                result = value.ToArray();
                return true;
            }

            result = null;
            return false;
        }

        public bool TryGetIPAddress(string name, [MaybeNullWhen(false)] out IPAddress result)
        {
            result = null;

            if (!Ref.TryGetBinary(name.AsSpan(), out ReadOnlySpan<byte> raw))
            {
                return false;
            }

            if (raw.Length != 4 && raw.Length != 16)
            {
                return false;
            }

            result = new IPAddress(raw.ToArray());
            return true;
        }

        public bool TryGetSocketAddress(string name, [MaybeNullWhen(false)] out SocketAddress result)
        {
            result = null;

            if (!Ref.TryGetBinary(name.AsSpan(), out ReadOnlySpan<byte> raw) || raw.Length < 2)
            {
                return false;
            }

            var family = (AddressFamily)(raw[0] | (raw[1] << 8));
            var address = new SocketAddress(family, raw.Length);

            for (int i = 0; i < raw.Length; i++)
            {
                address[i] = raw[i];
            }

            result = address;
            return true;
        }

        public IPAddress GetIPAddress(string name)
        {
            return TryGetIPAddress(name, out IPAddress? v) ? v : throw Missing(name);
        }

        public IPAddress GetIPAddress(string name, IPAddress defaultValue)
        {
            return TryGetIPAddress(name, out IPAddress? v) ? v : defaultValue;
        }

        public SocketAddress GetSocketAddress(string name)
        {
            return TryGetSocketAddress(name, out SocketAddress? v) ? v : throw Missing(name);
        }

        public SocketAddress GetSocketAddress(string name, SocketAddress defaultValue)
        {
            return TryGetSocketAddress(name, out SocketAddress? v) ? v : defaultValue;
        }

        /// <remarks>
        /// The C++/CLI implementation declared this as <c>DateTime^</c> — a boxed value type,
        /// which surfaces to C# as <see cref="ValueType"/>. Returning <see cref="DateTime"/>
        /// removes the boxing allocation, but is a breaking change for implementors of
        /// <see cref="IEventRecord"/>. See MIGRATION.md.
        /// </remarks>
        public DateTime GetDateTime(string name)
        {
            return TryGetDateTime(name, out DateTime v) ? v : throw Missing(name);
        }

        /// <inheritdoc cref="GetDateTime(string)"/>
        public DateTime GetDateTime(string name, DateTime defaultValue)
        {
            return TryGetDateTime(name, out DateTime v) ? v : defaultValue;
        }

        /// <inheritdoc cref="GetDateTime(string)"/>
        public bool TryGetDateTime(string name, out DateTime result)
        {
            result = default;

            if (!Ref.TryGetBinary(name.AsSpan(), out ReadOnlySpan<byte> raw))
            {
                return false;
            }

            if (raw.Length == 8)
            {
                long fileTime = 0;
                for (int i = 0; i < 8; i++)
                {
                    fileTime |= (long)raw[i] << (i * 8);
                }

                // Zero is a legitimate value: providers use it to mean "no time", and
                // FromFileTimeUtc renders it as the FILETIME epoch, which is what the
                // C++/CLI implementation returns. Only values it rejects outright are
                // reported as unreadable — negatives, and anything past 9999-12-31, which
                // has no DateTime to map to. Both would otherwise throw out of a TryGet.
                if (fileTime < 0 || fileTime > MaxRepresentableFileTime)
                {
                    return false;
                }

                result = DateTime.FromFileTimeUtc(fileTime);
                return true;
            }

            if (raw.Length == 16)
            {
                // SYSTEMTIME: eight little-endian UINT16 fields, with DayOfWeek at index 2.
                int year = raw[0] | (raw[1] << 8);
                int month = raw[2] | (raw[3] << 8);
                int day = raw[6] | (raw[7] << 8);
                int hour = raw[8] | (raw[9] << 8);
                int minute = raw[10] | (raw[11] << 8);
                int second = raw[12] | (raw[13] << 8);
                int millisecond = raw[14] | (raw[15] << 8);

                try
                {
                    result = new DateTime(year, month, day, hour, minute, second, millisecond, DateTimeKind.Utc);
                    return true;
                }
                catch (ArgumentOutOfRangeException)
                {
                    return false;
                }
            }

            return false;
        }

        #endregion

        private static ParserException Missing(string name)
        {
            return new ParserException("Could not find property in event schema: " + name);
        }
    }
}
