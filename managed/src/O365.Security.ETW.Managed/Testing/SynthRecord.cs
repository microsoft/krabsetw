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
        private IntPtr _record;
        private IntPtr _userData;
        private IntPtr _extendedData;

        internal SynthRecord(EVENT_HEADER header, byte[] userData, ExtendedDataBuilder extendedData)
        {
            _record = Marshal.AllocHGlobal(sizeof(EVENT_RECORD));
            var record = (EVENT_RECORD*)_record;
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
                    Marshal.FreeHGlobal(_record);
                    _record = IntPtr.Zero;

                    throw new ArgumentException(
                        "The event payload is " + userData.Length +
                        " bytes, and EVENT_RECORD.UserDataLength cannot describe more than " +
                        ushort.MaxValue + ".");
                }

                _userData = Marshal.AllocHGlobal(userData.Length);
                Marshal.Copy(userData, 0, _userData, userData.Length);
                record->UserData = _userData;
                record->UserDataLength = (ushort)userData.Length;
            }

            if (extendedData != null && extendedData.Count > 0)
            {
                _extendedData = extendedData.Pack();
                record->ExtendedData = _extendedData;
                record->ExtendedDataCount = (ushort)extendedData.Count;
            }
        }

        ~SynthRecord()
        {
            Free();
        }

        internal EVENT_RECORD* Record
        {
            get
            {
                if (_record == IntPtr.Zero)
                {
                    throw new ObjectDisposedException(nameof(SynthRecord));
                }

                return (EVENT_RECORD*)_record;
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

        public void Dispose()
        {
            Free();
            GC.SuppressFinalize(this);
        }

        private void Free()
        {
            if (_userData != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_userData);
                _userData = IntPtr.Zero;
            }

            if (_extendedData != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_extendedData);
                _extendedData = IntPtr.Zero;
            }

            if (_record != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_record);
                _record = IntPtr.Zero;
            }
        }
    }
}
