using System;
using System.Security.Cryptography;
using System.Text;

namespace Ngsoft.Security
{
    public class DataProtector
    {
        private readonly DataProtectionScope _scope;
        private readonly Encoding _encoding;
        private readonly byte[] _entropy;

        public DataProtector(bool isLocalMachineScope, Encoding encoding, byte[] entropy = null)
        {
            _scope = isLocalMachineScope ? DataProtectionScope.LocalMachine : DataProtectionScope.CurrentUser;
            _encoding = encoding ?? throw new ArgumentNullException(nameof(encoding));
            _entropy = entropy;
        }

        public byte[] ProtectData(string data)
        {
            if (string.IsNullOrWhiteSpace(data))
            {
                return new byte[0];
            }

            return ProtectedData.Protect(userData: _encoding.GetBytes(data), _entropy, _scope);
        }

        public string ProtectDataAsBase64(string data)
        {
            if (string.IsNullOrWhiteSpace(data))
            {
                return string.Empty;
            }

            var bytes = ProtectedData.Protect(userData: _encoding.GetBytes(data), _entropy, _scope);
            return Convert.ToBase64String(bytes);
        }

        public string UnprotectData(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return string.Empty;
            }

            var bytes = ProtectedData.Unprotect(encryptedData: data, _entropy, _scope);
            return _encoding.GetString(bytes);
        }

        public string UnprotectDataFromBase64(string data)
        {
            if (string.IsNullOrWhiteSpace(data))
            {
                return string.Empty;
            }

            var bytes = ProtectedData.Unprotect(encryptedData: Convert.FromBase64String(data), _entropy, _scope);
            return _encoding.GetString(bytes);
        }
    }
}
