using System;
using System.Collections.Generic;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Pins the exception types the managed port exposes for compatibility with callers that
    /// catch krabs-specific failures rather than plain <see cref="Exception"/>.
    /// </summary>
    public class KernelErrorsTests
    {
        private static readonly Type CppCliExposedExceptionBase = typeof(Exception);

        public static IEnumerable<object[]> ExceptionTypes()
        {
            yield return Row(typeof(TraceAlreadyRegistered));
            yield return Row(typeof(InvalidParameter));
            yield return Row(typeof(OpenTraceFailure));
            yield return Row(typeof(CouldNotFindSchema));
            yield return Row(typeof(UnexpectedError));
            yield return Row(typeof(ParserException));
            yield return Row(typeof(TypeMismatchAssert));
            yield return Row(typeof(ContainerIdFormatException));
            yield return Row(typeof(NoTraceSessionsRemaining));
        }

        [Theory]
        [MemberData(nameof(ExceptionTypes))]
        public void DefaultConstructorsCreateKrabsExceptionsWithMessages(Type exceptionType)
        {
            Assert.True(CppCliExposedExceptionBase.IsAssignableFrom(exceptionType));

            object instance = Activator.CreateInstance(exceptionType);
            Assert.IsType(exceptionType, instance);
            var ex = (Exception)instance;

            Assert.NotEmpty(ex.Message);
        }

        [Theory]
        [MemberData(nameof(ExceptionTypes))]
        public void MessageConstructorsPreserveTheProvidedMessage(Type exceptionType)
        {
            object instance = Activator.CreateInstance(exceptionType, "specific failure");
            Assert.IsType(exceptionType, instance);
            var ex = (Exception)instance;

            Assert.Equal("specific failure", ex.Message);
        }

        [Fact]
        public void TraceExceptionCarriesStatusInPropertyAndMessage()
        {
            TraceException ex = Assert.IsType<TraceException>(new TraceException("OpenTrace failed", 5));

            Assert.Equal(5, ex.Status);
            Assert.Contains("Status: 5", ex.Message, StringComparison.Ordinal);
        }

        private static object[] Row(Type exceptionType)
        {
            return new object[] { exceptionType };
        }
    }
}
