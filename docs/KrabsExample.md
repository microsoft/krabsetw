Guided Example
==============

ETW has the concept of a trace, where a trace essentially represents a stream of events that can be listened to. It distinguishes between kernel and user traces, where the source of events in a kernel trace comes from the Windows kernel. User trace event sources can be any regular application that is ETW-aware.

Krabs maintains the differentiation between user and kernel traces because their APIs are slightly different.

A `user_trace` can be named an arbitrary name or a name can be generated for you.

    user_trace trace(); // unnamed trace
    user_trace namedTrace(L"Muffins McGoo");

Krabs represents different sources of ETW events with the concept of a `provider`. Providers are identified by a GUID, as specified by ETW itself. Providers each have a pair of bitflags named `any` and `all` that are used to do event filtering. If an event meets any of the flags in the `any` flag, registered event callbacks are called. If an event meets all of the flags in the `all` flag, registered event callbacks are likewise called.

**NOTE:** The semantics of the `any` and `all` flag are left to the discretion of the ETW provider. Many providers ignore the `all` flag if the `any` flag is not set, for example.

    void mycallbackFunction(const EVENT_RECORD &)
    {}

    provider<> powershellProvider(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
    powershellProvider.any(0x10);
    powershellProvider.any(0x01); // augment the any flag
    powershellProvider.add_on_event_callback(mycallbackFunction);

Providers must be enabled for specific traces in order to have any effect on the event tracing system:

    namedTrace.enable(powershellProvider);

Once all the providers have been enabled for a trace, the trace must be started. The `user_trace::start()` method will block while listening for events, so if a program is supposed to do other interesting things while listening for ETW events, the start method needs to called on another thread.

    void startListening()
    {
        namedTrace.start();
    }

    std::thread t(startListening);
    sleep(1000);
    namedTrace.stop();
    t.join();