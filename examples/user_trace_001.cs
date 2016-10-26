// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a UserTrace to extract powershell command
// invocations.

using System;
using O365.Security.ETW;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // UserTrace instances should be used for any non-kernel traces that are defined
            // by components or programs in Windows.
            var trace = new UserTrace();

            // A trace can have any number of providers, which are identified by GUID. These
            // GUIDs are defined by the components that emit events, and their GUIDs can
            // usually be found with various ETW tools (like wevutil).
            var powershellProvider = new Provider(Guid.Parse("{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"));

            // UserTrace providers typically have any and all flags, whose meanings are
            // unique to the specific providers that are being invoked. To understand these
            // flags, you'll need to look to the ETW event producer.
            powershellProvider.Any = Provider.AllBitsSet;

            // Providers should be wired up to functions that are called when
            // events from that provider are fired.
            powershellProvider.OnEvent += (EventRecord record) =>
            {
                // Once an event is received, if we want krabs to help us analyze it, we need
                // to snap in a schema to ask it for information.
                var schema = new Schema(record);

                // We then have the ability to ask a few questions of the event.
                Console.WriteLine("Event " + schema.Id + " (" + schema.Name + ") received.");

                if (schema.Id == 7937)
                {
                    // The event we're interested in has a field that contains a bunch of
                    // info about what it's doing. We can snap in a parser to help us get
                    // the property information out.
                    var parser = new Parser(schema);

                    // We need to call the specific method to parse the type we expect.
                    // If we don't want to deal with the possibility of failure, we can
                    // provide a default if parsing fails.
                    var context = parser.ParseWStringWithDefault("ContextInfo", "None.");
                    Console.WriteLine("Context: " + context);
                }
            };

            // The UserTrace needs to know about the provider that we've set up.
            trace.Enable(powershellProvider);

            // Begin listening for events. This call blocks, so if you want to do other things
            // while this runs, you'll need to call this on another thread.
            trace.Start();
        }
    }
}
