using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace app.TcpOperations
{
    public class MyTcpClient
    {
        public bool IsReadyToWrite { get; set; }

        private readonly ILogger _logger;
        private readonly IPAddress _serverIp;
        private readonly int _serverPort;
        private readonly SemaphoreSlim _writeSemaphore = new(1, 1);
        private readonly CancellationTokenSource _cancellationTokenSource = new();

        private bool _isRunning;
        private bool _isExitSignaled;
        private NetworkStream _networkStream;

        /// <summary>
        /// Initializes a new instance of the MyTcpClient class
        /// </summary>
        /// <param name="logger">ILogger interface</param>
        /// <param name="serverIp">The target server IP. Pass null or emptry string to use loopback.</param>
        /// <param name="serverPort">The target server port</param>
        public MyTcpClient(ILogger logger, string serverIp, int serverPort)
        {
            _logger = logger;

            if (string.IsNullOrWhiteSpace(serverIp) ||
                !IPAddress.TryParse(serverIp, out _serverIp))
            {
                _serverIp = IPAddress.Loopback;
            }

            _serverPort = serverPort;
        }

        /// <summary>
        /// Start the client main loop to keep trying to connect and then receive until Stop() is called.
        /// If the loop is already running, this method returns immediately.
        /// This is usually called at a separate thread.
        /// </summary>
        public async Task RunAsync()
        {
            if (_isRunning)
            {
                return;
            }

            _logger.Log(LogLevel.Debug, "Starting....");

            _isRunning = true;
            _isExitSignaled = false;

            // The main loop to keep trying to connect to the server and then start receiving.
            while (!_isExitSignaled)
            {
                await HandleConnectionAttempAndReceiveAsync();
            }

            _isRunning = false;
            _logger.Log(LogLevel.Debug, "Stopped");
        }

        /// <summary>
        /// Stop the client.
        /// This will trigger the main Run thread to finish.
        /// </summary>
        public void Stop()
        {
            _isExitSignaled = true;

            try
            {
                _cancellationTokenSource.Cancel();
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
                _cancellationTokenSource.Dispose();
            }
            catch (Exception e)
            {
                _logger.Log(LogLevel.Trace, $"{e}");
            }
        }

        /// <summary>
        /// Write the data to the target server stream.
        /// </summary>
        /// <param name="buffer">The data buffer</param>
        /// <param name="offset">The offset in the buffer</param>
        /// <param name="length">The length of data to write</param>
        /// <returns></returns>
        public async Task WriteAsync(byte[] buffer, int offset, int length)
        {
            if (!IsReadyToWrite)
            {
                return;
            }

            // It is possible that the write is called by different threads. Thus, we use a semaphore to protect.
            await _writeSemaphore.WaitAsync(_cancellationTokenSource.Token);
            try
            {
                await _networkStream.WriteAsync(buffer.AsMemory(offset, length));
                await _networkStream.FlushAsync();
            }
            finally
            {
                _writeSemaphore.Release();
            }
        }

        /// <summary>
        /// Try connecting to the server and start receiving.
        /// </summary>
        private async Task HandleConnectionAttempAndReceiveAsync()
        {
            const int connectionAttempDelayInMilliSeconds = 1000;
            var tcpClient = new TcpClient();

            try
            {
                await tcpClient.ConnectAsync(_serverIp, _serverPort, _cancellationTokenSource.Token);

                if (!tcpClient.Connected)
                {
                    _logger.Log(LogLevel.Warning, $"Connection is not done. Retry.");
                    return;
                }

                _logger.Log(LogLevel.Debug, $"Connected to server {_serverIp}:{_serverPort}. Start receiving...");

                await ReceiveAsync(tcpClient);
            }
            catch (Exception e)
            {
                _logger.Log(LogLevel.Trace, $"{e}");
            }
            finally
            {
                tcpClient.Close();

                _logger.Log(LogLevel.Debug, $"Connection finished. Retry connecting...");
                Thread.Sleep(connectionAttempDelayInMilliSeconds);
            }
        }

        /// <summary>
        /// Start the receiving loop to receive the incoming data from the server.
        /// </summary>
        /// <param name="tcpClient">The target TcpClient</param>
        /// <returns></returns>
        private async Task ReceiveAsync(TcpClient tcpClient)
        {
            try
            {
                _networkStream = tcpClient.GetStream();
                IsReadyToWrite = true;

                // Start the loop to keep processing the incoming data from the server.
                var buffer = new Byte[256];
                int len;
                while ((len = await _networkStream.ReadAsync(buffer.AsMemory(0, buffer.Length),
                    _cancellationTokenSource.Token)) != 0 &&
                    !_isExitSignaled)
                {
                    ProcessData(buffer, len);
                }
            }
            catch (Exception e)
            {
                _logger.Log(LogLevel.Trace, $"{e}");
            }
            finally
            {
                IsReadyToWrite = false;
                _networkStream?.Close();
            }
        }

        /// <summary>
        /// Process the incoming data from the server.
        /// The logic in this method should be replaced with the target applicatoin data design.
        /// </summary>
        /// <param name="buffer">The incoming data buffer</param>
        /// <param name="length">The size of the data chunk</param>
        private void ProcessData(byte[] buffer, int length)
        {
            // Dummy processing for tutorial purpose.
            var dataString = System.Text.Encoding.ASCII.GetString(buffer, 0, length);
            _logger.Log(LogLevel.Information, $"Receives message from server: {dataString}");
        }
    }
}