// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;

namespace ApiDiff
{
    /// <summary>
    /// Dumps and compares the public surface of two assemblies.
    /// </summary>
    /// <remarks>
    /// Reads metadata directly rather than loading the assemblies, because one side is a
    /// mixed-mode C++/CLI binary that cannot be loaded for reflection on .NET, and because a
    /// comparison should not depend on either assembly's dependencies resolving.
    /// </remarks>
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.Error.WriteLine("usage: ApiDiff <assembly>                          # dump surface");
                Console.Error.WriteLine("       ApiDiff <baseline> <candidate>             # diff surfaces");
                Console.Error.WriteLine("       ApiDiff <baseline> <candidate> <approved>  # diff against approved list");
                return 2;
            }

            if (args.Length == 1)
            {
                foreach (string line in Surface(args[0]))
                {
                    Console.WriteLine(line);
                }

                return 0;
            }

            var baseline = new SortedSet<string>(Surface(args[0]), StringComparer.Ordinal);
            var candidate = new SortedSet<string>(Surface(args[1]), StringComparer.Ordinal);

            var differences = new List<string>();
            differences.AddRange(baseline.Except(candidate, StringComparer.Ordinal).Select(l => "- " + l));
            differences.AddRange(candidate.Except(baseline, StringComparer.Ordinal).Select(l => "+ " + l));
            differences.Sort(StringComparer.Ordinal);

            if (args.Length == 2)
            {
                foreach (string line in differences)
                {
                    Console.WriteLine(line);
                }

                Console.Error.WriteLine(
                    $"baseline {baseline.Count}, candidate {candidate.Count}, differences {differences.Count}");

                return differences.Count == 0 ? 0 : 1;
            }

            return Approve(differences, args[2]);
        }

        /// <summary>
        /// Compares the differences against a checked-in list of ones that have been reviewed.
        /// </summary>
        /// <remarks>
        /// The two implementations are not expected to converge — the port drops surface that
        /// nothing consumes. What must not happen is a difference appearing that nobody looked
        /// at, so the list is the gate rather than an empty diff.
        /// </remarks>
        private static int Approve(List<string> differences, string approvedPath)
        {
            var approved = File.ReadAllLines(approvedPath)
                .Select(l => l.Trim())
                .Where(l => l.Length > 0 && !l.StartsWith("#", StringComparison.Ordinal))
                .ToList();

            var unapproved = differences.Except(approved, StringComparer.Ordinal).ToList();
            var stale = approved.Except(differences, StringComparer.Ordinal).ToList();

            foreach (string line in unapproved)
            {
                Console.Error.WriteLine("UNAPPROVED  " + line);
            }

            foreach (string line in stale)
            {
                Console.Error.WriteLine("STALE       " + line);
            }

            if (unapproved.Count == 0 && stale.Count == 0)
            {
                Console.Error.WriteLine($"{differences.Count} differences, all approved.");
                return 0;
            }

            Console.Error.WriteLine(
                $"{unapproved.Count} unapproved difference(s), {stale.Count} stale entr(y|ies). " +
                "Review, then regenerate with: ApiDiff <baseline> <candidate> > ApprovedDifferences.txt");

            return 1;
        }

        private static IEnumerable<string> Surface(string path)
        {
            using var stream = File.OpenRead(path);
            using var pe = new PEReader(stream);
            MetadataReader md = pe.GetMetadataReader();
            var provider = new SignatureProvider(md);
            var lines = new List<string>();

            foreach (TypeDefinitionHandle handle in md.TypeDefinitions)
            {
                TypeDefinition type = md.GetTypeDefinition(handle);
                if (!IsVisible(md, type))
                {
                    continue;
                }

                string name = TypeName(md, type);
                lines.Add(
                    $"type {Kind(md, type)} {name}{BaseSuffix(md, type, provider)}" +
                    Attributes(md, type.GetCustomAttributes(), provider));

                foreach (FieldDefinitionHandle fh in type.GetFields())
                {
                    FieldDefinition field = md.GetFieldDefinition(fh);
                    if (!IsVisible(field.Attributes))
                    {
                        continue;
                    }

                    string fieldType = field.DecodeSignature(provider, null);
                    lines.Add(
                        $"field {name}.{md.GetString(field.Name)} : {fieldType}" +
                        Attributes(md, field.GetCustomAttributes(), provider));
                }

                foreach (MethodDefinitionHandle mh in type.GetMethods())
                {
                    MethodDefinition method = md.GetMethodDefinition(mh);
                    if (!IsVisible(method.Attributes))
                    {
                        continue;
                    }

                    MethodSignature<string> sig = method.DecodeSignature(provider, null);
                    string parameters = string.Join(", ", sig.ParameterTypes);
                    lines.Add(
                        $"method {name}.{md.GetString(method.Name)}({parameters}) : {sig.ReturnType}" +
                        Attributes(md, method.GetCustomAttributes(), provider));
                }
            }

            return lines;
        }

        /// <summary>
        /// Renders the custom attributes that change how a consumer may use the member.
        /// </summary>
        /// <remarks>
        /// Deliberately a fixed list rather than everything. C++/CLI and Roslyn each emit their
        /// own bookkeeping attributes, and rendering those would report differences that no
        /// consumer can observe.
        /// </remarks>
        private static string Attributes(
            MetadataReader md, CustomAttributeHandleCollection handles, SignatureProvider provider)
        {
            var names = new List<string>();

            foreach (CustomAttributeHandle handle in handles)
            {
                CustomAttribute attribute = md.GetCustomAttribute(handle);
                string name = AttributeTypeName(md, attribute, provider);

                if (!Significant.Contains(name))
                {
                    continue;
                }

                if (name == "System.ObsoleteAttribute")
                {
                    string message = ObsoleteMessage(attribute, provider);

                    // Roslyn stamps this on every ref struct when the target framework has no
                    // IsByRefLikeAttribute. It is a down-level compiler guard, not a deprecation,
                    // and it appears on net462/net48 but not net10.
                    if (message != null && message.StartsWith(
                        "Types with embedded references are not supported", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    names.Add(message == null ? "[Obsolete]" : $"[Obsolete(\"{message}\")]");
                    continue;
                }

                names.Add("[" + name + "]");
            }

            names.Sort(StringComparer.Ordinal);
            return names.Count == 0 ? string.Empty : " " + string.Join(" ", names);
        }

        private static string ObsoleteMessage(CustomAttribute attribute, SignatureProvider provider)
        {
            try
            {
                CustomAttributeValue<string> value = attribute.DecodeValue(provider);
                return value.FixedArguments.Length > 0 ? value.FixedArguments[0].Value as string : null;
            }
            catch (BadImageFormatException)
            {
                return null;
            }
        }

        private static readonly HashSet<string> Significant = new HashSet<string>(StringComparer.Ordinal)
        {
            "System.ObsoleteAttribute",
            "System.FlagsAttribute",
            "System.ParamArrayAttribute",
            "System.Runtime.CompilerServices.ExtensionAttribute",
        };

        private static string AttributeTypeName(
            MetadataReader md, CustomAttribute attribute, SignatureProvider provider)
        {
            switch (attribute.Constructor.Kind)
            {
                case HandleKind.MethodDefinition:
                    MethodDefinition def = md.GetMethodDefinition((MethodDefinitionHandle)attribute.Constructor);
                    return provider.FromHandle(def.GetDeclaringType());
                case HandleKind.MemberReference:
                    MemberReference reference = md.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
                    return provider.FromHandle(reference.Parent);
                default:
                    return "?";
            }
        }

        private static string BaseSuffix(MetadataReader md, TypeDefinition type, SignatureProvider provider)
        {
            var parts = new List<string>();

            if (!type.BaseType.IsNil)
            {
                string baseName = provider.FromHandle(type.BaseType);

                // Every value type and enum derives from these; noise rather than surface.
                if (baseName != "System.Object" && baseName != "System.ValueType" && baseName != "System.Enum")
                {
                    parts.Add(baseName);
                }
            }

            foreach (InterfaceImplementationHandle ih in type.GetInterfaceImplementations())
            {
                InterfaceImplementation impl = md.GetInterfaceImplementation(ih);
                parts.Add(provider.FromHandle(impl.Interface));
            }

            parts.Sort(StringComparer.Ordinal);
            return parts.Count == 0 ? string.Empty : " : " + string.Join(", ", parts);
        }

        private static string Kind(MetadataReader md, TypeDefinition type)
        {
            if ((type.Attributes & TypeAttributes.Interface) != 0)
            {
                return "interface";
            }

            if (!type.BaseType.IsNil)
            {
                var provider = new SignatureProvider(md);
                string baseName = provider.FromHandle(type.BaseType);
                if (baseName == "System.Enum")
                {
                    return "enum";
                }

                if (baseName == "System.ValueType")
                {
                    return "struct";
                }

                if (baseName == "System.MulticastDelegate")
                {
                    return "delegate";
                }
            }

            return "class";
        }

        private static bool IsVisible(MetadataReader md, TypeDefinition type)
        {
            TypeAttributes visibility = type.Attributes & TypeAttributes.VisibilityMask;

            if (visibility == TypeAttributes.Public)
            {
                return true;
            }

            if (visibility == TypeAttributes.NestedPublic ||
                visibility == TypeAttributes.NestedFamily ||
                visibility == TypeAttributes.NestedFamORAssem)
            {
                TypeDefinitionHandle declaring = type.GetDeclaringType();
                return !declaring.IsNil && IsVisible(md, md.GetTypeDefinition(declaring));
            }

            return false;
        }

        private static bool IsVisible(FieldAttributes attributes)
        {
            FieldAttributes access = attributes & FieldAttributes.FieldAccessMask;
            return access == FieldAttributes.Public
                || access == FieldAttributes.Family
                || access == FieldAttributes.FamORAssem;
        }

        private static bool IsVisible(MethodAttributes attributes)
        {
            MethodAttributes access = attributes & MethodAttributes.MemberAccessMask;
            return access == MethodAttributes.Public
                || access == MethodAttributes.Family
                || access == MethodAttributes.FamORAssem;
        }

        private static string TypeName(MetadataReader md, TypeDefinition type)
        {
            string name = md.GetString(type.Name);
            TypeDefinitionHandle declaring = type.GetDeclaringType();

            if (!declaring.IsNil)
            {
                return TypeName(md, md.GetTypeDefinition(declaring)) + "+" + name;
            }

            string ns = md.GetString(type.Namespace);
            return string.IsNullOrEmpty(ns) ? name : ns + "." + name;
        }
    }
}
