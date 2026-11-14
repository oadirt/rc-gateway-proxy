// Loaded into the proxy under test only (node --import): the name api.anthropic.com resolves to
// this machine, so the proxy talks to the stand-in in run.mjs and can never reach the real host.
import dns from 'node:dns';
const real = dns.lookup;
dns.lookup = (host, options, callback) => {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (host !== 'api.anthropic.com') return real(host, options, callback);
  if (options && options.all) return callback(null, [{ address: '127.0.0.1', family: 4 }]);
  return callback(null, '127.0.0.1', 4);
};
