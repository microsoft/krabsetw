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
                Console.Error.WriteLine("usage: ApiDiff <assembly>              # dump surface");
                Console.Error.WriteLine("       ApiDiff <baseline> <candidate>  # diff surfaces");
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

            var missing = baseline.Except(candidate, StringComparer.Ordinal).ToList();
            var added = candidate.Except(baseline, StringComparer.Ordinal).ToList();

            foreach (string line in missing)
            {
                Console.WriteLine("- " + line);
            }

            foreach (string line in added)
            {
                Console.WriteLine("+ " + line);
            }

            Console.Error.WriteLine(
                $"baseline {baseline.Count}, candidate {candidate.Count}, missing {missing.Count}, added {added.Count}");

            return missing.Count == 0 && added.Count == 0 ? 0 : 1;
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
                lines.Add($"type {Kind(md, type)} {name}{BaseSuffix(md, type, provider)}");

                foreach (FieldDefinitionHandle fh in type.GetFields())
                {
                    FieldDefinition field = md.GetFieldDefinition(fh);
                    if (!IsVisible(field.Attributes))
                    {
                        continue;
                    }

                    string fieldType = field.DecodeSignature(provider, null);
                    lines.Add($"field {name}.{md.GetString(field.Name)} : {fieldType}");
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
                        $"method {name}.{md.GetString(method.Name)}({parameters}) : {sig.ReturnType}");
                }
            }

            return lines;
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
