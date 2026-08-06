// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Immutable;
using System.Reflection.Metadata;
using System.Text;

namespace ApiDiff
{
    /// <summary>
    /// Renders metadata signatures as stable, comparable strings.
    /// </summary>
    internal sealed class SignatureProvider :
        ISignatureTypeProvider<string, object>, ICustomAttributeTypeProvider<string>
    {
        private readonly MetadataReader reader;

        public SignatureProvider(MetadataReader reader)
        {
            this.reader = reader;
        }

        public string FromHandle(EntityHandle handle)
        {
            switch (handle.Kind)
            {
                case HandleKind.TypeDefinition:
                    return this.GetTypeFromDefinition(this.reader, (TypeDefinitionHandle)handle, 0);
                case HandleKind.TypeReference:
                    return this.GetTypeFromReference(this.reader, (TypeReferenceHandle)handle, 0);
                case HandleKind.TypeSpecification:
                    return this.GetTypeFromSpecification(this.reader, null, (TypeSpecificationHandle)handle, 0);
                default:
                    return "?";
            }
        }

        public string GetPrimitiveType(PrimitiveTypeCode typeCode)
        {
            switch (typeCode)
            {
                case PrimitiveTypeCode.Boolean: return "System.Boolean";
                case PrimitiveTypeCode.Byte: return "System.Byte";
                case PrimitiveTypeCode.Char: return "System.Char";
                case PrimitiveTypeCode.Double: return "System.Double";
                case PrimitiveTypeCode.Int16: return "System.Int16";
                case PrimitiveTypeCode.Int32: return "System.Int32";
                case PrimitiveTypeCode.Int64: return "System.Int64";
                case PrimitiveTypeCode.IntPtr: return "System.IntPtr";
                case PrimitiveTypeCode.Object: return "System.Object";
                case PrimitiveTypeCode.SByte: return "System.SByte";
                case PrimitiveTypeCode.Single: return "System.Single";
                case PrimitiveTypeCode.String: return "System.String";
                case PrimitiveTypeCode.TypedReference: return "System.TypedReference";
                case PrimitiveTypeCode.UInt16: return "System.UInt16";
                case PrimitiveTypeCode.UInt32: return "System.UInt32";
                case PrimitiveTypeCode.UInt64: return "System.UInt64";
                case PrimitiveTypeCode.UIntPtr: return "System.UIntPtr";
                case PrimitiveTypeCode.Void: return "System.Void";
                default: return typeCode.ToString();
            }
        }

        public string GetTypeFromDefinition(MetadataReader md, TypeDefinitionHandle handle, byte rawTypeKind)
        {
            TypeDefinition type = md.GetTypeDefinition(handle);
            string name = md.GetString(type.Name);
            TypeDefinitionHandle declaring = type.GetDeclaringType();

            if (!declaring.IsNil)
            {
                return this.GetTypeFromDefinition(md, declaring, 0) + "+" + name;
            }

            string ns = md.GetString(type.Namespace);
            return string.IsNullOrEmpty(ns) ? name : ns + "." + name;
        }

        public string GetTypeFromReference(MetadataReader md, TypeReferenceHandle handle, byte rawTypeKind)
        {
            TypeReference type = md.GetTypeReference(handle);
            string name = md.GetString(type.Name);

            if (type.ResolutionScope.Kind == HandleKind.TypeReference)
            {
                return this.GetTypeFromReference(md, (TypeReferenceHandle)type.ResolutionScope, 0) + "+" + name;
            }

            string ns = md.GetString(type.Namespace);
            return string.IsNullOrEmpty(ns) ? name : ns + "." + name;
        }

        public string GetTypeFromSpecification(
            MetadataReader md, object genericContext, TypeSpecificationHandle handle, byte rawTypeKind)
        {
            return md.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
        }

        public string GetSZArrayType(string elementType) => elementType + "[]";

        public string GetArrayType(string elementType, ArrayShape shape)
            => elementType + "[" + new string(',', Math.Max(0, shape.Rank - 1)) + "]";

        public string GetByReferenceType(string elementType) => elementType + "&";

        public string GetPointerType(string elementType) => elementType + "*";

        public string GetPinnedType(string elementType) => elementType + " pinned";

        public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments)
            => genericType + "<" + string.Join(", ", typeArguments) + ">";

        public string GetGenericMethodParameter(object genericContext, int index) => "!!" + index;

        public string GetGenericTypeParameter(object genericContext, int index) => "!" + index;

        // Custom modifiers (modopt/modreq) are an encoding detail of the declaring compiler, not
        // part of the surface a C# caller binds against. C++/CLI emits IsConst and friends that
        // Roslyn never would, so including them would report differences that do not exist.
        public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType;

        public string GetFunctionPointerType(MethodSignature<string> signature)
            => "delegate*<" + string.Join(", ", signature.ParameterTypes) + ", " + signature.ReturnType + ">";

        public string GetSystemType() => "System.Type";

        public bool IsSystemType(string type) => type == "System.Type";

        public string GetTypeFromSerializedName(string name) => name;

        public PrimitiveTypeCode GetUnderlyingEnumType(string type) => PrimitiveTypeCode.Int32;
    }
}
