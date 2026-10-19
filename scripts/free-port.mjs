// Print a free loopback TCP port. Used by scripts/conformance-run.sh because
// the SUT's config (parsePort) rejects 0 and inline `node -e` is unavailable.
import net from 'node:net';

const server = net.createServer();
server.listen(0, '127.0.0.1', () => {
  const port = server.address().port;
  server.close(() => process.stdout.write(String(port)));
});
