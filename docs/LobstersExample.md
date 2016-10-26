Guided Example
==============

*Note: This example is intentionally a carbon copy of the KrabsExample.md since krabs concepts map directly into O365.Security.Native.ETW functionality.*

ETW has the concept of a trace, where a trace essentially represents a stream of events that can be listened to. It distinguishes between kernel and user traces, where the source of events in a kernel trace comes from the Windows kernel. User trace event sources can be any regular application that is ETW-aware.

O365.Security.Native.ETW maintains the differentiation between user and kernel traces because their APIs are slightly different.

A `UserTrace` can be named an arbitrary name or a name can be generated for you.

    var trace = new UserTrace(); // unnamed trace
    var namedTrace = new UserTrace("Muffins McGoo");

O365.Security.Native.ETW represents different sources of ETW events with the concept of a `Provider`. Providers are identified by a GUID, as specified by ETW itself. Providers each have a pair of bitflags named `Any` and `All` that are used to do event filtering. If an event meets any of the flags in the `Any` flag, registered event callbacks are called. If an event meets all of the flags in the `All` flag, registered event callbacks are likewise called.

**NOTE:** The semantics of the `Any` and `All` flag are left to the discretion of the ETW provider. Many providers ignore the `All` flag if the `Any` flag is not set, for example.

    void OnEventRecord(IEventRecord record)
    {}

	var trace = new UserTrace();
	var provider = new Provider(Guid.Parse("{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"));
    provider.All = 0x10;
	provider.Any = 0x01; // augment the Any flag.
    provider.OnEvent += OnEventRecord;

Providers must be enabled for specific traces in order to have any effect on the event tracing system:

    namedTrace.Enable(provider);

Once all the providers have been enabled for a trace, the trace must be started. The `UserTrace.Start()` method **will block while listening for events**, so if a program is supposed to do other interesting things while listening for ETW events, the start method needs to called on another thread.

    void startListening()
    {
        namedTrace.Start();
    }

    var task = await Task.Factory.StartNew(() => startListening(), TaskCreationOptions.LongRunning);
    sleep(1000);
    namedTrace.Stop();
    task.Wait();