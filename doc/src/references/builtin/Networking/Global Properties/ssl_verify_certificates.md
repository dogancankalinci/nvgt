# ssl_verify_certificates
Whether the certificates of the servers your game connects to over TLS are checked.

`bool ssl_verify_certificates;`

## Remarks:
This covers every secure client connection NVGT makes: `url_get()`, `url_post()` and `url_request()` with an https address, the `http` and `https_client` classes, secure web sockets, streaming a sound from an https address, and sending mail over TLS.

When it is true, a connection to a server whose certificate is expired, self-signed, issued by an authority the system doesn't trust, or revoked fails, as it does in a web browser. This is what keeps someone between the player and your server (a hostile Wi-Fi network or router) from standing in for your update, login or download server. When it is false, any certificate is accepted: the connection is still encrypted, but nothing proves who is on the other end.

On Windows the certificates are checked against the system's trusted root certificates, and this property is true by default. On other platforms NVGT has no certificate store to check against, so the default is false; setting it to true there loads OpenSSL's default certificate locations, and a system that keeps its trusted certificates elsewhere (Android and iOS, and possibly some Linux distributions and macOS) then refuses every server.

Set it to false only while testing against a development server with a self-signed certificate, and never in a released game that sends passwords or downloads files.
