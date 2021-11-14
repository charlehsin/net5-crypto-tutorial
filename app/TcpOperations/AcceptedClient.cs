using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace app.TcpOperations
{
    public class AcceptedClient : IDisposable
    {
        private readonly ILogger _logger;
        private readonly string _clientId;
        private readonly BufferedStream _bufferedStream;
        private readonly SemaphoreSlim _writeSemaphore = new(1, 1);
        private readonly CancellationTokenSource _writeCancellationTokenSource = new();

        private bool _disposed;

        /// <summary>
        /// Initialize a new instance of AcceptedClient object.
        /// </summary>
        /// <param name="logger">ILogger interface.</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="BufferedStream">The stream of the remote client.</param>
        public AcceptedClient(ILogger logger,
                              string clientId,
                              BufferedStream bufferedStream)
        {
            _logger = logger;
            _clientId = clientId;
            _bufferedStream = bufferedStream;
        }

        /// <summary>
        /// Get the client ID based on remote ip:port.
        /// We are assuming that for the same remote ip:port, there will only be 1 client connecting.
        /// If this is not true, the unique string may need to be changed.
        /// </summary>
        /// <param name="ipEndPoint">The remote IP endpoint.</param>
        /// <returns>The client ID.</returns>
        public static string GetClientId(IPEndPoint ipEndPoint)
        {
            return $"{ipEndPoint.Address}:{ipEndPoint.Port}";
        }

        /// <summary>
        /// Process the incoming data for this client.
        /// The logic in this method should be replaced with the target applicatoin data design.
        /// </summary>
        /// <param name="buffer">The incoming data buffer.</param>
        /// <param name="length">The size of the data chunk.</param>
        public void ProcessData(byte[] buffer,
                                int length)
        {
            // Dummy processing for tutorial purpose.
            var dataString = System.Text.Encoding.ASCII.GetString(buffer, 0, length);
            _logger.Log(LogLevel.Information, $"Receives message from Client {_clientId}: {dataString}");
        }

        /// <summary>
        /// Write the data to the target client stream.
        /// </summary>
        /// <param name="buffer">The data buffer.</param>
        /// <param name="offset">The offset in the buffer.</param>
        /// <param name="length">The length of data to write.</param>
        /// <returns></returns>
        public async Task WriteAsync(byte[] buffer,
                                     int offset,
                                     int length)
        {
            // It is possible that the write is called by different threads. Thus, we use a semaphore to protect.
            await _writeSemaphore.WaitAsync(_writeCancellationTokenSource.Token);
            try
            {
                await _bufferedStream.WriteAsync(buffer.AsMemory(offset, length));
                await _bufferedStream.FlushAsync();
            }
            finally
            {
                _writeSemaphore.Release();
            }
        }

        /// <summary>
        /// Proper implementation of IDisposable from MSDN.
        /// </summary>
        public void Dispose()
        {
            // Dispose of unmanaged resources.
            Dispose(true);
            // Suppress finalization.
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Proper implementation of IDisposable from MSDN.
        /// </summary>
        /// <param name="disposing">True to dispose managed resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                // Dispose managed state (managed objects).

                try
                {
                    _writeCancellationTokenSource.Cancel();
                }
                catch (Exception e)
                {
                    _logger.Log(LogLevel.Trace, $"{e}");
                }

                try
                {
                    _writeSemaphore.Dispose();
                }
                catch (Exception e)
                {
                    _logger.Log(LogLevel.Trace, $"{e}");
                }

                try
                {
                    _writeCancellationTokenSource.Dispose();
                }
                catch (Exception e)
                {
                    _logger.Log(LogLevel.Trace, $"{e}");
                }
            }

            // TODO: Free unmanaged resources (unmanaged objects) and override a finalizer below.
            // Set large fields to null.

            _disposed = true;
        }
    }
}