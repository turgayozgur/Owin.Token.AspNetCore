using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Owin.Token.AspNetCore
{
    /// <summary>
    /// LegacyAuthTokenHelper
    /// </summary>
    public class LegacyOAuthSecurityTokenHelper
    {
        #region Public Methods

        /// <summary>
        /// Get Deserialized Ticket from token.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static AuthenticationTicket GetTicket(string token, LegacyTokenAuthenticationOptions options)
        {
            if (string.IsNullOrWhiteSpace(token)) throw new ArgumentNullException(nameof(token));
            if (options == null) throw new ArgumentNullException(nameof(options));
            if (string.IsNullOrWhiteSpace(options.DecryptionKey)) throw new ArgumentNullException(options.DecryptionKey);
            if (string.IsNullOrWhiteSpace(options.ValidationKey)) throw new ArgumentNullException(options.ValidationKey);
            
            var encryptionKey = DeriveKey(new CryptographicKey(HexToBinary(options.DecryptionKey)));
            var validationKey = DeriveKey(new CryptographicKey(HexToBinary(options.ValidationKey)));

            var raw = Unprotect(Base64UrlTextDecode(token), encryptionKey, validationKey,
                new CryptoAlgorithmFactory(options));
            
            if (raw == null) throw new CryptographicException();

            var ticket = TicketSerializer.Deserialize(raw);

            return ticket;
        }

        #endregion Public Methods
        
        #region Unprotect
        
        private static byte[] Unprotect(byte[] protectedData, CryptographicKey decryptionKey, CryptographicKey validationKey, 
            CryptoAlgorithmFactory cryptoAlgorithmFactory)
        {
            // The entire operation is wrapped in a 'checked' block because any overflows should be treated as failures.
            checked
            {

                // We want to check that the input is in the form:
                // protectedData := IV || Enc(Kenc, IV, clearData) || Sign(Kval, IV || Enc(Kenc, IV, clearData))

                // Definitions used in this method:
                // encryptedPayload := Enc(Kenc, IV, clearData)
                // signature := Sign(Kval, IV || encryptedPayload)

                // These SymmetricAlgorithm instances are single-use; we wrap it in a 'using' block.
                using (var decryptionAlgorithm = cryptoAlgorithmFactory.GetEncryptionAlgorithm())
                {
                    decryptionAlgorithm.Key = decryptionKey.GetKeyMaterial();

                    // These KeyedHashAlgorithm instances are single-use; we wrap it in a 'using' block.
                    using (var validationAlgorithm = cryptoAlgorithmFactory.GetValidationAlgorithm())
                    {
                        validationAlgorithm.Key = validationKey.GetKeyMaterial();

                        // First, we need to verify that protectedData is even long enough to contain
                        // the required components (IV, encryptedPayload, signature).

                        var ivByteCount = decryptionAlgorithm.BlockSize / 8; // IV length is equal to the block size
                        var signatureByteCount = validationAlgorithm.HashSize / 8;
                        var encryptedPayloadByteCount = protectedData.Length - ivByteCount - signatureByteCount;
                        if (encryptedPayloadByteCount <= 0)
                        {
                            // protectedData doesn't meet minimum length requirements
                            return null;
                        }

                        // If that check passes, we need to detect payload tampering.

                        // Compute the signature over the IV and encrypted payload
                        // computedSignature := Sign(Kval, IV || encryptedPayload)
                        var computedSignature = validationAlgorithm.ComputeHash(protectedData, 0, ivByteCount + encryptedPayloadByteCount);

                        if (!BuffersAreEqual(
                            buffer1: protectedData, buffer1Offset: ivByteCount + encryptedPayloadByteCount, buffer1Count: signatureByteCount,
                            buffer2: computedSignature, buffer2Offset: 0, buffer2Count: computedSignature.Length))
                        {

                            // the computed signature didn't match the incoming signature, which is a sign of payload tampering
                            return null;
                        }

                        // At this point, we're certain that we generated the signature over this payload,
                        // so we can go ahead with decryption.

                        // Populate the IV from the incoming stream
                        var iv = new byte[ivByteCount];
                        Buffer.BlockCopy(protectedData, 0, iv, 0, iv.Length);
                        decryptionAlgorithm.IV = iv;

                        // Write the decrypted payload to the memory stream.
                        using (var memStream = new MemoryStream())
                        {
                            using (var decryptor = decryptionAlgorithm.CreateDecryptor())
                            {
                                using (var cryptoStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Write))
                                {
                                    cryptoStream.Write(protectedData, ivByteCount, encryptedPayloadByteCount);
                                    cryptoStream.FlushFinalBlock();

                                    // At this point
                                    // memStream := clearData

                                    var clearData = memStream.ToArray();
                                    return clearData;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        /// Determines if two buffer instances are equal, e.g. whether they contain the same payload. This method
        /// is written in such a manner that it should take the same amount of time to execute regardless of
        /// whether the result is success or failure. The modulus operation is intended to make the check take the
        /// same amount of time, even if the buffers are of different lengths.
        ///
        /// !! DO NOT CHANGE THIS METHOD WITHOUT SECURITY 
        [MethodImpl(MethodImplOptions.NoOptimization)]
        private static bool BuffersAreEqual(byte[] buffer1, int buffer1Offset, int buffer1Count, byte[] buffer2, int buffer2Offset, int buffer2Count)
        {
            var success = (buffer1Count == buffer2Count); // can't possibly be successful if the buffers are of different lengths
            for (var i = 0; i < buffer1Count; i++)
            {
                success &= (buffer1[buffer1Offset + i] == buffer2[buffer2Offset + (i % buffer2Count)]);
            }
            return success;
        }

        #endregion Unprotect
        
        #region DeriveKey
        
        private static CryptographicKey DeriveKey(CryptographicKey key)
        {
            using (var hmac = new HMACSHA512(key.GetKeyMaterial()))
            {
                GetKeyDerivationParameters(out var label, out var context);

                var derivedKey = DeriveKeyImpl(hmac, label, context, key.KeyLength);
                return new CryptographicKey(derivedKey);
            }
        }
        
        private static void GetKeyDerivationParameters(out byte[] label, out byte[] context)
        {
            label = Encoding.UTF8.GetBytes("User.MachineKey.Protect");
            using (var memoryStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(memoryStream, Encoding.UTF8))
                {
                    foreach (var specificPurpose in new[]
                    {
                        "Microsoft.Owin.Security.OAuth",
                        "Access_Token",
                        "v1"
                    })
                    {
                        binaryWriter.Write(specificPurpose);
                    }
                    context = memoryStream.ToArray();
                }
            }
        }
        
        private static byte[] DeriveKeyImpl(HMAC hmac, byte[] label, byte[] context, int keyLengthInBits)
        {
            checked
            {
                var labelLength = label?.Length ?? 0;
                var contextLength = context?.Length ?? 0;
                var buffer = new byte[4 /* [i]_2 */ + labelLength /* label */ + 1 /* 0x00 */ + contextLength /* context */ + 4 /* [L]_2 */];

                if (labelLength != 0)
                {
                    Buffer.BlockCopy(label, 0, buffer, 4, labelLength); // the 4 accounts for the [i]_2 length
                }
                if (contextLength != 0)
                {
                    Buffer.BlockCopy(context, 0, buffer, 5 + labelLength, contextLength); // the '5 +' accounts for the [i]_2 length, the label, and the 0x00 byte
                }
                WriteUInt32ToByteArrayBigEndian((uint)keyLengthInBits, buffer, 5 + labelLength + contextLength); // the '5 +' accounts for the [i]_2 length, the label, the 0x00 byte, and the context

                // Initialization

                var numBytesWritten = 0;
                var numBytesRemaining = keyLengthInBits / 8;
                var output = new byte[numBytesRemaining];

                // Calculate each K_i value and copy the leftmost bits to the output buffer as appropriate.

                for (uint i = 1; numBytesRemaining > 0; i++)
                {
                    WriteUInt32ToByteArrayBigEndian(i, buffer, 0); // set the first 32 bits of the buffer to be the current iteration value
                    var kI = hmac.ComputeHash(buffer);

                    // copy the leftmost bits of K_i into the output buffer
                    var numBytesToCopy = Math.Min(numBytesRemaining, kI.Length);
                    Buffer.BlockCopy(kI, 0, output, numBytesWritten, numBytesToCopy);
                    numBytesWritten += numBytesToCopy;
                    numBytesRemaining -= numBytesToCopy;
                }

                // finished
                return output;
            }
        }
        
        private static void WriteUInt32ToByteArrayBigEndian(uint value, byte[] buffer, int offset)
        {
            buffer[offset + 0] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)(value);
        }
        
        #endregion DeriveKey

        #region Utils

        /// <summary>
        /// Converts a hexadecimal string into its binary representation.
        /// </summary>
        /// <param name="data">The hex string.</param>
        /// <returns>The byte array corresponding to the contents of the hex string,
        /// or null if the input string is not a valid hex string.</returns>
        private static byte[] HexToBinary(string data)
        {
            if (data == null || data.Length % 2 != 0)
            {
                // input string length is not evenly divisible by 2
                return null;
            }

            var binary = new byte[data.Length / 2];

            for (var i = 0; i < binary.Length; i++)
            {
                var highNibble = HexToInt(data[2 * i]);
                var lowNibble = HexToInt(data[2 * i + 1]);

                if (highNibble == -1 || lowNibble == -1)
                {
                    return null; // bad hex data
                }
                binary[i] = (byte)((highNibble << 4) | lowNibble);
            }

            return binary;
        }
        
        // https://github.com/Microsoft/referencesource/blob/master/System.Web/Util/HttpEncoderUtility.cs
        private static int HexToInt(char h)
        {
            return (h >= '0' && h <= '9') ? h - '0' :
                (h >= 'a' && h <= 'f') ? h - 'a' + 10 :
                (h >= 'A' && h <= 'F') ? h - 'A' + 10 :
                -1;
        }
        
        public static byte[] Base64UrlTextDecode(string text)
        {
            return Convert.FromBase64String(Pad(text.Replace('-', '+').Replace('_', '/')));
        }
        
        private static string Pad(string text)
        {
            var padding = 3 - ((text.Length + 3) % 4);
            if (padding == 0)
            {
                return text;
            }
            return text + new string('=', padding);
        }

        #endregion Utils
    }
}