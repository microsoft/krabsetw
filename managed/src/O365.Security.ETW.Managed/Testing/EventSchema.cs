using System;
using System.Collections.Generic;
using System.Threading;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;

namespace Microsoft.O365.Security.ETW.Testing
{
    /// <summary>
    /// A schema declared by a test rather than read from the machine's registered providers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="RecordBuilder"/> and every property accessor resolve an event's layout
    /// through TDH, so both building and reading a record normally require the provider's
    /// manifest to be installed. A declared schema removes that requirement: while it is in
    /// scope it answers for the events it describes, which lets tests cover providers that
    /// are absent from build agents, that vary by Windows release, or that do not exist at
    /// all.
    /// </para>
    /// <para>
    /// A declaration is only as accurate as whoever wrote it. It describes what the test
    /// believes the event looks like, so a declaration that has drifted from the real
    /// manifest will produce a passing test against an event shape that is never emitted.
    /// Prefer a real in-box provider where one exists, and keep declarations close to the
    /// template they mirror.
    /// </para>
    /// </remarks>
    public sealed unsafe class EventSchema
    {
        private const int PropertyInfoSize = 24;

        private readonly Guid _providerId;
        private readonly ushort _id;
        private readonly byte _version;
        private readonly string _providerName;
        private readonly List<Property> _properties = new List<Property>();
        private string? _eventName;
        private byte[]? _blob;

        private EventSchema(string providerName, Guid providerId, int id, int version)
        {
            if (id < 0 || id > ushort.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(id));
            }

            if (version < 0 || version > byte.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(version));
            }

            _providerName = providerName ?? string.Empty;
            _providerId = providerId;
            _id = (ushort)id;
            _version = (byte)version;
        }

        /// <summary>
        /// Begins a declaration for one event of one provider.
        /// </summary>
        public static EventSchema Create(string providerName, Guid providerId, int id, int version = 0)
        {
            return new EventSchema(providerName, providerId, id, version);
        }

        /// <summary>
        /// Brings declarations into scope for the current execution context, and takes them
        /// back out when the returned value is disposed.
        /// </summary>
        /// <remarks>
        /// Scoping is per execution context rather than global, so tests running in parallel
        /// do not see one another's declarations. A declaration therefore does not reach a
        /// live trace's processing thread, which needs no declaration in any case: events
        /// delivered by ETW come from providers that are registered by definition.
        /// </remarks>
        public static IDisposable Use(params EventSchema[] schemas)
        {
            if (schemas == null)
            {
                throw new ArgumentNullException(nameof(schemas));
            }

            for (int i = 0; i < schemas.Length; i++)
            {
                if (schemas[i] == null)
                {
                    throw new ArgumentException("A declaration was null.", nameof(schemas));
                }

                // Fail here rather than at pack time, where the error would surface as a
                // missing schema.
                schemas[i].Blob();
            }

            return DeclaredSchemas.Push(schemas);
        }

        /// <summary>Sets the event name reported by <c>EventRecordRef.Name</c>.</summary>
        public EventSchema Named(string eventName)
        {
            _eventName = eventName;
            _blob = null;
            return this;
        }

        public EventSchema Int8(string name) => Add(name, TdhInType.Int8);

        public EventSchema UInt8(string name) => Add(name, TdhInType.UInt8);

        public EventSchema Int16(string name) => Add(name, TdhInType.Int16);

        public EventSchema UInt16(string name) => Add(name, TdhInType.UInt16);

        public EventSchema Int32(string name) => Add(name, TdhInType.Int32);

        public EventSchema UInt32(string name) => Add(name, TdhInType.UInt32);

        public EventSchema Int64(string name) => Add(name, TdhInType.Int64);

        public EventSchema UInt64(string name) => Add(name, TdhInType.UInt64);

        public EventSchema Float(string name) => Add(name, TdhInType.Float);

        public EventSchema Double(string name) => Add(name, TdhInType.Double);

        public EventSchema Boolean(string name) => Add(name, TdhInType.Boolean);

        public EventSchema Guid(string name) => Add(name, TdhInType.Guid);

        public EventSchema Pointer(string name) => Add(name, TdhInType.Pointer);

        public EventSchema FileTime(string name) => Add(name, TdhInType.FileTime);

        public EventSchema SystemTime(string name) => Add(name, TdhInType.SystemTime);

        public EventSchema Sid(string name) => Add(name, TdhInType.Sid);

        public EventSchema HexInt32(string name) => Add(name, TdhInType.HexInt32);

        public EventSchema HexInt64(string name) => Add(name, TdhInType.HexInt64);

        /// <summary>
        /// Declares a NUL terminated string property, or a string sized by an earlier
        /// property when <paramref name="lengthFrom"/> is given.
        /// </summary>
        public EventSchema UnicodeString(string name, string? lengthFrom = null)
        {
            return AddString(name, TdhInType.UnicodeString, lengthFrom);
        }

        /// <inheritdoc cref="UnicodeString(string, string)"/>
        public EventSchema AnsiString(string name, string? lengthFrom = null)
        {
            return AddString(name, TdhInType.AnsiString, lengthFrom);
        }

        /// <summary>
        /// Declares a binary property of a fixed width, or one sized by an earlier property
        /// when <paramref name="lengthFrom"/> is given.
        /// </summary>
        public EventSchema Binary(string name, int length = 0, string? lengthFrom = null)
        {
            if (length < 0 || length > ushort.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            if (lengthFrom != null)
            {
                return AddString(name, TdhInType.Binary, lengthFrom);
            }

            return Add(name, TdhInType.Binary, (ushort)length, 0);
        }

        internal bool Describes(Guid providerId, ushort id, byte version)
        {
            return _id == id && _version == version && _providerId == providerId;
        }

        /// <summary>
        /// The declaration rendered as a TRACE_EVENT_INFO, in the form TDH would have
        /// returned. Built once and reused; every cache takes its own unmanaged copy.
        /// </summary>
        internal byte[] Blob()
        {
            return _blob ?? (_blob = Render());
        }

        private EventSchema AddString(string name, TdhInType inType, string? lengthFrom)
        {
            if (lengthFrom == null)
            {
                return Add(name, inType);
            }

            int index = IndexOf(lengthFrom);

            if (index < 0)
            {
                throw new ArgumentException(
                    "Property " + name + " is sized by " + lengthFrom +
                    ", which must be declared before it.", nameof(lengthFrom));
            }

            return Add(name, inType, (ushort)index, NativeConstants.PropertyParamLength);
        }

        private EventSchema Add(string name, TdhInType inType, ushort length = 0, uint flags = 0)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("A property needs a name.", nameof(name));
            }

            if (IndexOf(name) >= 0)
            {
                throw new ArgumentException("Property " + name + " is declared twice.", nameof(name));
            }

            _properties.Add(new Property(name, inType, length, flags));
            _blob = null;
            return this;
        }

        private int IndexOf(string name)
        {
            for (int i = 0; i < _properties.Count; i++)
            {
                if (string.Equals(_properties[i].Name, name, StringComparison.Ordinal))
                {
                    return i;
                }
            }

            return -1;
        }

        private byte[] Render()
        {
            int propertyArray = TraceEventInfoLayout.PropertyArrayOffset;
            int stringsAt = propertyArray + (_properties.Count * PropertyInfoSize);

            var strings = new List<string>();
            var offsets = new List<int>();
            int cursor = stringsAt;

            int Intern(string? value)
            {
                if (string.IsNullOrEmpty(value))
                {
                    return 0;
                }

                strings.Add(value!);
                offsets.Add(cursor);
                int at = cursor;
                cursor += (value!.Length + 1) * 2;
                return at;
            }

            int providerNameOffset = Intern(_providerName);
            int eventNameOffset = Intern(_eventName);
            var propertyNameOffsets = new int[_properties.Count];

            for (int i = 0; i < _properties.Count; i++)
            {
                propertyNameOffsets[i] = Intern(_properties[i].Name);
            }

            var blob = new byte[cursor];

            fixed (byte* p = blob)
            {
                var info = (TRACE_EVENT_INFO*)p;
                info->ProviderGuid = _providerId;
                info->EventDescriptor.Id = _id;
                info->EventDescriptor.Version = _version;
                info->ProviderNameOffset = (uint)providerNameOffset;
                info->EventNameOffset = (uint)eventNameOffset;
                info->PropertyCount = (uint)_properties.Count;
                info->TopLevelPropertyCount = (uint)_properties.Count;

                var props = (EVENT_PROPERTY_INFO*)(p + propertyArray);

                for (int i = 0; i < _properties.Count; i++)
                {
                    Property property = _properties[i];

                    props[i].Flags = property.Flags;
                    props[i].NameOffset = (uint)propertyNameOffsets[i];
                    props[i].InTypeOrStructStartIndex = (ushort)property.InType;
                    props[i].OutTypeOrNumOfStructMembers = 0;
                    props[i].LengthOrLengthPropertyIndex = property.Length;
                    props[i].CountOrCountPropertyIndex = 0;
                }

                for (int i = 0; i < strings.Count; i++)
                {
                    var destination = (char*)(p + offsets[i]);
                    string value = strings[i];

                    for (int c = 0; c < value.Length; c++)
                    {
                        destination[c] = value[c];
                    }

                    destination[value.Length] = '\0';
                }
            }

            return blob;
        }

        private readonly struct Property
        {
            public readonly string Name;
            public readonly TdhInType InType;
            public readonly ushort Length;
            public readonly uint Flags;

            public Property(string name, TdhInType inType, ushort length, uint flags)
            {
                Name = name;
                InType = inType;
                Length = length;
                Flags = flags;
            }
        }
    }

    /// <summary>
    /// The declarations currently in scope. Consulted by the schema cache on a miss, before
    /// TDH is asked.
    /// </summary>
    internal static class DeclaredSchemas
    {
        private static readonly AsyncLocal<EventSchema[]?> Current = new AsyncLocal<EventSchema[]?>();

        /// <summary>
        /// Whether any declaration is in scope. Read on the miss path only, so a trace that
        /// never declares a schema pays a single null check per distinct event.
        /// </summary>
        public static bool Any
        {
            get { return Current.Value != null; }
        }

        public static EventSchema? Find(Guid providerId, ushort id, byte version)
        {
            EventSchema[]? scope = Current.Value;

            if (scope == null)
            {
                return null;
            }

            // Later declarations win, so a test can narrow one already in scope.
            for (int i = scope.Length - 1; i >= 0; i--)
            {
                if (scope[i].Describes(providerId, id, version))
                {
                    return scope[i];
                }
            }

            return null;
        }

        public static IDisposable Push(EventSchema[] schemas)
        {
            EventSchema[]? outer = Current.Value;

            if (outer == null || outer.Length == 0)
            {
                Current.Value = schemas;
            }
            else
            {
                var combined = new EventSchema[outer.Length + schemas.Length];
                Array.Copy(outer, combined, outer.Length);
                Array.Copy(schemas, 0, combined, outer.Length, schemas.Length);
                Current.Value = combined;
            }

            return new Scope(outer);
        }

        private sealed class Scope : IDisposable
        {
            private readonly EventSchema[]? _outer;
            private bool _disposed;

            public Scope(EventSchema[]? outer)
            {
                _outer = outer;
            }

            public void Dispose()
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                Current.Value = _outer;
            }
        }
    }
}
