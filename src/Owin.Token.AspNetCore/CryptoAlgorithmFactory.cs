using System;
using System.IO;
using System.Security.Cryptography;

namespace Owin.Token.AspNetCore
{
    /// <summary>
    /// CryptoAlgorithmFactory
    /// </summary>
    internal sealed class CryptoAlgorithmFactory
    {
        private readonly LegacyTokenAuthenticationOptions _options;
        
        private Func<SymmetricAlgorithm> _encryptionAlgorithmFactory;
        private Func<KeyedHashAlgorithm> _validationAlgorithmFactory;

        /// <summary>
        /// CryptoAlgorithmFactory
        /// </summary>
        /// <param name="options"></param>
        public CryptoAlgorithmFactory(LegacyTokenAuthenticationOptions options)
        {
            _options = options;
        }
        
        /// <summary>
        /// GetEncryptionAlgorithm
        /// </summary>
        /// <returns></returns>
        public SymmetricAlgorithm GetEncryptionAlgorithm()
        {
            if (_encryptionAlgorithmFactory == null)
            {
                _encryptionAlgorithmFactory = GetEncryptionAlgorithmFactory();
            }
            return _encryptionAlgorithmFactory();
        }

        private Func<SymmetricAlgorithm> GetEncryptionAlgorithmFactory()
        {
            switch (_options.EncryptionMethod)
            {
                case EncryptionMethod.AES:
                    return Aes.Create;
                case EncryptionMethod.TripleDES:
                    return TripleDES.Create;
                default:
                    throw new InvalidDataException("EncryptionMethod");
            }
        }

        /// <summary>
        /// GetValidationAlgorithm
        /// </summary>
        /// <returns></returns>
        public KeyedHashAlgorithm GetValidationAlgorithm()
        {
            if (_validationAlgorithmFactory == null)
            {
                _validationAlgorithmFactory = GetValidationAlgorithmFactory();
            }
            return _validationAlgorithmFactory();
        }

        private Func<KeyedHashAlgorithm> GetValidationAlgorithmFactory()
        {
            switch (_options.ValidationMethod)
            {
                case ValidationMethod.SHA1:
                    return () => new HMACSHA1();
                case ValidationMethod.HMACSHA256:
                    return () => new HMACSHA256();
                case ValidationMethod.HMACSHA384:
                    return () => new HMACSHA384();
                case ValidationMethod.HMACSHA512:
                    return () => new HMACSHA512();
                default:
                    throw new InvalidDataException("ValidationMethod");
            }
        }
    }
    
    /// <summary>
    /// EncryptionMethod
    /// </summary>
    public enum EncryptionMethod
    {
        /// <summary>
        /// AES
        /// </summary>
        AES,
        /// <summary>
        /// TripleDES
        /// </summary>
        TripleDES
    }
    
    /// <summary>
    /// ValidationMethod
    /// </summary>
    public enum ValidationMethod
    {
        /// <summary>
        /// SHA1
        /// </summary>
        SHA1,
        /// <summary>
        /// HMACSHA256
        /// </summary>
        HMACSHA256,
        /// <summary>
        /// HMACSHA384
        /// </summary>
        HMACSHA384,
        /// <summary>
        /// HMACSHA512
        /// </summary>
        HMACSHA512
    }
}