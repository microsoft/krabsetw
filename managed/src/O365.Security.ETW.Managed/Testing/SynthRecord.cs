using System;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW.Interop;

namespace Microsoft.O365.Security.ETW.Testing
{
    /// <summary>
    /// A hand-built event record, for testing code that reacts to events without needing a
    /// live ETW session.
    /// </summary>
    /// <remarks>
    /// Use a <see cref="RecordBuilder"/> to get one. The backing EVENT_RECORD, its user data
    /// and its extended data all live in unmanaged memory, so the record can be handed
    /// straight to the same dispatch path a real event takes.
    /// </remarks>
    public sealed unsafe class SynthRecord : IDisposable
    {
        private SafeHGlobalHandle? _record;
        private SafeHGlobalHandle? _userData;
        private SafeHGlobalHandle? _extendedData;

        internal SynthRecord(EVENT_HEADER header, byte[] userData, ExtendedDataBuilder extendedData)
        {
            _record = new SafeHGlobalHandle(sizeof(EVENT_RECORD));
            var record = (EVENT_RECORD*)_record.Pointer;
            *record = default(EVENT_RECORD);
            record->EventHeader = header;

            if (record->EventHeader.Size == 0)
            {
                record->EventHeader.Size = (ushort)sizeof(EVENT_HEADER);
            }

            if (userData != null && userData.Length > 0)
            {
                // UserDataLength is a USHORT. Casting a longer payload into it wraps, and the
                // record then decodes as a much shorter one, with every property past the
                // wrapped length reported absent for no visible reason.
                if (userData.Length > ushort.MaxValue)
                {
                    _record.Dispose();
                    _record = null;

                    throw new ArgumentException(
                        "The event payload is " + userData.Length +
                        " bytes, and EVENT_RECORD.UserDataLength cannot describe more than " +
                        ushort.MaxValue + ".");
                }

                _userData = new SafeHGlobalHandle(userData.Length);
                Marshal.Copy(userData, 0, _userData.Pointer, userData.Length);
                record->UserData = _userData.Pointer;
                record->UserDataLength = (ushort)userData.Length;
            }

            if (extendedData != null && extendedData.Count > 0)
            {
                // Pack returns null only for an empty builder, which Count has just excluded.
                _extendedData = extendedData.Pack()!;
                record->ExtendedData = _extendedData.Pointer;
                record->ExtendedDataCount = (ushort)extendedData.Count;
            }
        }

        internal EVENT_RECORD* Record
        {
            get
            {
                if (_record == null)
                {
                    throw new ObjectDisposedException(nameof(SynthRecord));
                }

                return (EVENT_RECORD*)_record.Pointer;
            }
        }

        /// <summary>Direct access to the underlying EVENT_RECORD's ProviderId.</summary>
        public Guid ProviderId
        {
            get { return Record->EventHeader.ProviderId; }
            set { Record->EventHeader.ProviderId = value; }
        }

        /// <summary>Direct access to the underlying EVENT_RECORD's Id.</summary>
        public ushort Id
        {
            get { return Record->EventHeader.EventDescriptor.Id; }
            set { Record->EventHeader.EventDescriptor.Id = value; }
        }

        /// <summary>Direct access to the underlying EVENT_RECORD's Version.</summary>
        public byte Version
        {
            get { return Record->EventHeader.EventDescriptor.Version; }
            set { Record->EventHeader.EventDescriptor.Version = value; }
        }

        /// <summary>Direct access to the underlying EVENT_RECORD's Opcode.</summary>
        public byte Opcode
        {
            get { return Record->EventHeader.EventDescriptor.Opcode; }
            set { Record->EventHeader.EventDescriptor.Opcode = value; }
        }

        /// <summary>Direct access to the underlying EVENT_RECORD's Flags.</summary>
        public ushort Flags
        {
            get { return Record->EventHeader.Flags; }
            set { Record->EventHeader.Flags = value; }
        }

        /// <summary>
        /// Releases the record's unmanaged memory.
        /// </summary>
        /// <remarks>
        /// No finalizer: each allocation is a <see cref="SafeHGlobalHandle"/> and releases
        /// itself through its own critical finalizer if the record is abandoned. Disposing
        /// here just makes it deterministic, which matters because a record is usually built
        /// and read inside one test.
        /// </remarks>
        public void Dispose()
        {
            _userData?.Dispose();
            _userData = null;

            _extendedData?.Dispose();
            _extendedData = null;

            _record?.Dispose();
            _record = null;
        }
    }
}
