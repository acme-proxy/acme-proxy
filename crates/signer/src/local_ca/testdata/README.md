# `local_ca` test fixtures

CA certificates made by `openssl`, not rcgen, because rcgen cannot write the
subjects these fixtures need. Nothing here is a real CA: each key was generated
for the test and certifies nothing.

Each one was made with this command, varying only `-subj`. The keys were
thrown away (`*.key` is ignored by git anyway), since only the subject is
under test:

```bash
openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout <name>.key -out <name>.pem -days 36500 -subj '<subject>' \
  -addext 'basicConstraints=critical,CA:true,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash'
```

| File | `-subj` |
|---|---|
| `repeated_dc_ca.pem` | `/DC=com/DC=example/O=ExampleCorp/CN=Issuing CA` |
| `multi_valued_rdn_ca.pem` | `/DC=com/DC=example/O=ExampleCorp/OU=PKI+CN=Issuing CA` |
| `openssl_ca.pem` | `/C=FR/O=Example/CN=Issuing CA` |

The first two are the subjects from issue #36. rcgen 0.14 cannot carry either
one (rustls/rcgen#81). `openssl_ca.pem` is an ordinary imported CA that must
still load.
