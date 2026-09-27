// c2_probe.js — definitive runtime probe: WHY is C2 traffic invisible?
// Usage: PC frida (USB, app process) OR via gadget. Run AFTER app launch.
//   frida -U -f com.nivaroid.topfollow -l c2_probe.js   (spawn)
// or:  frida -U -n <procname> -l c2_probe.js            (attach)
// What it answers (all hooks are on concrete, non-minified classes):
//   [URL]  what C2 base URL the native q.e() actually returns
//   [DNS]  which hosts the app resolves (C2 domain?)
//   [TCP]  every TCP connection attempt (C2 host:port?)
//   [TLS]  every TLS handshake attempt (C2 SNI?)
//   [C2]   direct C2 service interface call (y9.j) — best-effort
// If [TCP]/[TLS] show nivafollower-app.com attempts  -> request IS sent; capture-side issue.
// If NOTHING for the C2 domain                          -> request never sent; native/trigger suppression.
Java.perform(function () {
  function log(tag, msg) { console.log('[' + tag + '] ' + msg); }

  // 1) native C2 base URL (the ONLY native network dependency)
  try {
    var q = Java.use('com.nivaroid.topfollow.helper.q');
    ['e', 'f', 'g'].forEach(function (m) {
      try {
        q[m].overloads.forEach(function (ov) {
          ov.implementation = function () {
            var r = ov.apply(this, arguments);
            log('URL', 'q.' + m + '() => ' + r);
            return r;
          };
        });
      } catch (e) { /* method may not exist */ }
    });
  } catch (e) { log('ERR', 'q hook: ' + e); }

  // 2) DNS
  try {
    var InetAddress = Java.use('java.net.InetAddress');
    InetAddress.getAllByName.overload('java.lang.String').implementation = function (host) {
      log('DNS', 'resolve ' + host);
      return this.getAllByName(host);
    };
  } catch (e) { log('ERR', 'dns hook: ' + e); }

  // 3) every TCP connect
  try {
    var Socket = Java.use('java.net.Socket');
    Socket.connect.overload('java.net.InetSocketAddress').implementation = function (addr) {
      log('TCP', 'connect -> ' + (addr.getHostString ? addr.getHostString() : addr) + ':' + addr.getPort());
      return this.connect(addr);
    };
  } catch (e) { log('ERR', 'socket hook: ' + e); }

  // 4) every TLS handshake
  try {
    var SSLSocket = Java.use('javax.net.ssl.SSLSocket');
    SSLSocket.startHandshake.implementation = function () {
      try { log('TLS', 'handshake -> ' + this.getPeerHost() + ':' + this.getPort()); } catch (e) {}
      var r;
      try { r = this.startHandshake(); } catch (e) { log('TLS', '  !! FAILED: ' + e); throw e; }
      return r;
    };
  } catch (e) { log('ERR', 'ssl hook: ' + e); }

  // 5) C2 service interface (minified y9.j) — best effort
  try {
    var y9j = Java.use('y9.j');
    Object.keys(y9j).forEach(function (m) {
      if (m.indexOf('<') === 0) return;
      try {
        y9j[m].overloads.forEach(function (ov) {
          ov.implementation = function () {
            log('C2', 'y9.j.' + m + '() CALLED');
            return ov.apply(this, arguments);
          };
        });
      } catch (e) {}
    });
  } catch (e) { log('ERR', 'y9.j hook: ' + e); }

  log('OK', 'probes installed — now use the app (login, open screens, do actions)');
});
