using System;

namespace Dkbe.Certifier.Storage
{
    public class StorageException : Exception
    {
        public bool IsUnsealException { get; }

        public StorageException(string message) : base(message)
        {
        }

        public StorageException(string message, bool unsealException) : base(message)
        {
            IsUnsealException = unsealException;
        }

        public StorageException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public StorageException()
        {
        }
    }
}
