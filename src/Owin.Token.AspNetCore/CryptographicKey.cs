namespace Owin.Token.AspNetCore
{
    /// <summary>
    /// CryptographicKey
    /// </summary>
    internal class CryptographicKey
    {
        private readonly byte[] _keyMaterial;

        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="keyMaterial"></param>
        public CryptographicKey(byte[] keyMaterial)
        {
            _keyMaterial = keyMaterial;
        }

        /// <summary>
        /// Returns the length of the key (in bits).
        /// </summary>
        public int KeyLength => checked(_keyMaterial.Length * 8);

        /// <summary>
        /// Returns the raw key material as a byte array.
        /// </summary>
        /// <returns></returns>
        public byte[] GetKeyMaterial() => _keyMaterial;
    }
}