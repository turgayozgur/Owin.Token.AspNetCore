using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Claims;

namespace Owin.Token.AspNetCore
{
    /// <summary>
    /// TicketSerializer
    /// </summary>
    internal class TicketSerializer
    {
        private const int FormatVersion = 3;

        /// <summary>
        /// Deserialize
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static AuthenticationTicket Deserialize(byte[] data)
        {
            using (var memory = new MemoryStream(data))
            {
                using (var compression = new GZipStream(memory, CompressionMode.Decompress))
                {
                    using (var reader = new BinaryReader(compression))
                    {
                        return Read(reader);
                    }
                }
            }
        }

        /// <summary>
        /// Read
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static AuthenticationTicket Read(BinaryReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            if (reader.ReadInt32() != FormatVersion)
            {
                return null;
            }

            var authenticationType = reader.ReadString();
            var nameClaimType = ReadWithDefault(reader, DefaultValues.NameClaimType);
            var roleClaimType = ReadWithDefault(reader, DefaultValues.RoleClaimType);
            var count = reader.ReadInt32();
            var claims = new Claim[count];
            for (var index = 0; index != count; ++index)
            {
                var type = ReadWithDefault(reader, nameClaimType);
                var value = reader.ReadString();
                var valueType = ReadWithDefault(reader, DefaultValues.StringValueType);
                var issuer = ReadWithDefault(reader, DefaultValues.LocalAuthority);
                var originalIssuer = ReadWithDefault(reader, issuer);
                claims[index] = new Claim(type, value, valueType, issuer, originalIssuer);
            }
            var identity = new ClaimsIdentity(claims, authenticationType, nameClaimType, roleClaimType);
            var bootstrapContextSize = reader.ReadInt32();
            if (bootstrapContextSize > 0)
            {
                identity.BootstrapContext = reader.ReadString();
            }

            var properties = PropertiesSerializer.Read(reader);
            return new AuthenticationTicket(identity, properties);
        }

        private static string ReadWithDefault(BinaryReader reader, string defaultValue)
        {
            var value = reader.ReadString();
            return string.Equals(value, DefaultValues.DefaultStringPlaceholder, StringComparison.Ordinal) ? defaultValue : value;
        }

        private static class DefaultValues
        {
            public const string DefaultStringPlaceholder = "\0";
            public const string NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
            public const string RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
            public const string LocalAuthority = "LOCAL AUTHORITY";
            public const string StringValueType = "http://www.w3.org/2001/XMLSchema#string";
        }
    }
    
    /// <summary>
    /// PropertiesSerializer
    /// </summary>
    internal class PropertiesSerializer
    {
        private const int FormatVersion = 1;

        /// <summary>
        /// Deserialize
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public AuthenticationProperties Deserialize(byte[] data)
        {
            using (var memory = new MemoryStream(data))
            {
                using (var reader = new BinaryReader(memory))
                {
                    return Read(reader);
                }
            }
        }

        /// <summary>
        /// Read
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static AuthenticationProperties Read(BinaryReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            if (reader.ReadInt32() != FormatVersion)
            {
                return null;
            }
            var count = reader.ReadInt32();
            var extra = new Dictionary<string, string>(count);
            for (var index = 0; index != count; ++index)
            {
                var key = reader.ReadString();
                var value = reader.ReadString();
                extra.Add(key, value);
            }
            return new AuthenticationProperties(extra);
        }
    }
}