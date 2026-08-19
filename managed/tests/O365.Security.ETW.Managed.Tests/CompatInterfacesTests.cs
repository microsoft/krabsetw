using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the small value object exposed by the compat interface surface.
    /// </summary>
    public class CompatInterfacesTests
    {
        [Fact]
        public void PropertyStoresSchemaNameTypesAndLength()
        {
            var property = new Property("Payload", inType: 14, outType: 0, length: 4);

            Assert.Equal("Payload", property.Name);
            Assert.Equal(14u, property.InType);
            Assert.Equal(0u, property.OutType);
            Assert.Equal(4u, property.Length);
        }
    }
}
