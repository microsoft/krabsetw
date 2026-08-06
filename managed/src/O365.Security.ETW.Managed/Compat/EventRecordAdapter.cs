using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
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

        private EventRecordRef Ref
        {
            get
            {
                if (_record == null)
                {
                    throw new InvalidOperationException(
                        "This event record is no longer valid. It points at a buffer owned by ETW " +
                        "that is only live for the duration of the callback. Copy what you need " +
                        "before returning, or use EventRecordRef.");
                }

                return new EventRecordRef(_record, _scratch);
            }
        }

        #region Metadata

        public ushort Id => Ref.Id;

        public byte Opcode => Ref.Opcode;

        public byte Version => Ref.Version;

        public byte Level => Ref.Level;

        public ushort Flags => Ref.Flags;

        public EventHeaderProperty EventProperty => (EventHeaderProperty)Ref.EventProperty;

        public uint ProcessId => Ref.ProcessId;

        public uint ThreadId => Ref.ThreadId;

        public DateTime Timestamp => Ref.Timestamp;

        public Guid ProviderId => Ref.ProviderId;

        public Guid ActivityId => Ref.ActivityId;

        public ushort UserDataLength => Ref.UserDataLength;

        public IntPtr UserData => Ref.UserData;

        public DecodingSource GetEventType()
        {
            return Ref.GetEventType();
        }

        public List<ulong> GetStackTrace()
        {
            return ExtendedData.GetStackTrace(_record);
        }

        public byte[] CopyUserData()
        {
            return Ref.UserDataSpan.ToArray();
        }

        public bool TryGetContainerId(out Guid result)
        {
            return ExtendedData.TryGetContainerId(_record, out result);
        }

        public bool TryGetProcessStartKey(out ulong result)
        {
            return ExtendedData.TryGetProcessStartKey(_record, out result);
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

        public ReadOnlySpan<char> GetUnicodeString(ReadOnlySpan<char> name)
        {
            return Ref.GetUnicodeString(name);
        }

        public bool TryGetUnicodeString(ReadOnlySpan<char> name, out ReadOnlySpan<char> value)
        {
            return Ref.TryGetUnicodeString(name, out value);
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

        public ReadOnlySpan<char> GetCountedString(ReadOnlySpan<char> name)
        {
            return Ref.GetCountedString(name);
        }

        public bool TryGetCountedString(ReadOnlySpan<char> name, out ReadOnlySpan<char> value)
        {
            return Ref.TryGetCountedString(name, out value);
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
            if (Ref.TryGetAnsiStringBytes(name.AsSpan(), out ReadOnlySpan<byte> value))
            {
                result = value.Length == 0 ? string.Empty : Decode(value);
                return true;
            }

            result = null;
            return false;
        }

        public bool TryGetAnsiStringBytes(ReadOnlySpan<char> name, out ReadOnlySpan<byte> value)
        {
            return Ref.TryGetAnsiStringBytes(name, out value);
        }

        /// <summary>
        /// ANSI string properties carry the provider's ANSI code page, not UTF-8 -- see
        /// <see cref="Interop.AnsiEncoding"/> for the citation and the provider survey.
        /// </summary>
        private static string Decode(ReadOnlySpan<byte> value)
        {
            fixed (byte* p = value)
            {
                return Interop.AnsiEncoding.Current.GetString(p, value.Length);
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

        public bool TryGetBinary(ReadOnlySpan<char> name, out ReadOnlySpan<byte> value)
        {
            return Ref.TryGetBinary(name, out value);
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
        /// <see cref="IEventRecord"/>. See PARITY.md.
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

                if (fileTime <= 0)
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
