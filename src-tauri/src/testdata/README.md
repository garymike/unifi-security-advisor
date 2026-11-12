Throwaway self-signed certificates for the pinning tests in `connection.rs`
and `pinning.rs`. Each is a P-256 key and certificate for `127.0.0.1`,
generated for these tests only and used nowhere else. The keys are not
secrets: they protect nothing.

Regenerate with:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout k.pem -out c.pem -days 36500 -subj "/CN=test-console-a" -addext "subjectAltName=IP:127.0.0.1"
```

then convert to DER (`openssl x509 -outform DER`, `openssl pkcs8 -topk8 -nocrypt -outform DER`)
and update the expected fingerprint in `pinning.rs`.
