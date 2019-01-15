namespace Owin.Token.AspNetCore
{
    /// <summary>
    /// LegacyTokenAuthenticationOptions
    /// </summary>
    public class LegacyTokenAuthenticationOptions
    {
        /// <summary>
        /// EncryptionMethod from old machinekey section. Default, AES.
        /// </summary>
        public EncryptionMethod EncryptionMethod { get; set; } = EncryptionMethod.AES;

        /// <summary>
        /// ValidationMethod from old machinekey section. Default, HMACSHA256.
        /// </summary>
        public ValidationMethod ValidationMethod { get; set; } = ValidationMethod.HMACSHA256;

        /// <summary>
        /// DecryptionKey from old machinekey section.
        /// </summary>
        public string DecryptionKey { get; set; }

        /// <summary>
        /// ValidationKey from old machinekey section.
        /// </summary>
        public string ValidationKey { get; set; }
    }
}