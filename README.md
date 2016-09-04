# Ceylon crypto

Implementation of cryptographic algorithms/mechanisms in the Ceylon language.

SHA-1, SHA-256 and RSA signature (RSASSA-PSS and RSASSA-PKCS1-v1_5 from PKCS #1) algorithms and schemes are implemented.

The implementation section still needs much cleanup.

Note that IANAC (I am not a cryptologist), so this will surely be flawed in some security relevant way.

**Do not use in production and don't rely on it in any expensive way whatsoever!**

## Changes

* 2016-06-08 added most things needed ASN.1 to encode and decode X.509 certificates.
  Supports certificates signed with RSASSA-PSS!
  Still need support for X.500 names (AttributeValueAssertions with well-known object identifiers).
  Right now, only common name (2.5.4.3), country (2.5.4.6) and organization (2.5.4.10) are supported.
  No specific v3 extensions support yet. Need to implement some standard and well-known types.
  UTCTime is not finished
* Removed erroneous and unnecessary dependency from api to impl module

* added some ASN.1 (primitives and PKCS #1) stuff
* implemented RSA signature scheme RSASSA-PKCS1-v1_5
* now SHA-1 is also implemented, to be able to use the test vectors for PKCS #1
* new interface `MessageDigester`.
* implemented RSA signature according to PKCS #1 v2.2, signature scheme RSASSA-PSS
* Defined API interfaces/classes for hash functions and signatures as well as
  asymmetric keys. Modelled after the Java package java.security.
* split up to 3 modules: API, implementation and "service manager" to avoid cycles in the
  module dependencies (still in search of a good name for the "service manager" module)
* added separate test-source directory for tests (still need to move several tests from source to test-source)
* added examples directory with example for RSA signature

## SHA-256

This is implemented in a very straightforward way from the
description of the algorithm, see [Wikipedia entry](https://en.wikipedia.org/wiki/SHA-2) or
[this document](https://web.archive.org/web/20150315061807/http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf).

Very crude tests on the JVM backend indicate that it runs at about 1/3 the speed of the standard Java implementation.

It runs using the JVM and the JavaScript runtime.

### Usage

```
import de.dlkw.ccrypto.svc {
    sha256
}

shared void run() {
    value digester = sha256();
    digester.update({#61.byte, #62.byte});
    Byte[] digest = digester.digest({#63.byte});
}
```

That is:

   1. Obtain an instance of the algorithm. For example,
          
       `value digester = sha256();`
          
   2. Call the `update({Byte*})` method as often as you
       need, to transfer the whole message in arbitrarily
       sized parts to the algorithm.
       
   3. Obtain the resulting value---message digest (hash)---by calling `digest({Byte*})`.
      The argument to `digest()` is optional, defaulting
      to an empty message part.
       
   4. You can then reuse the algorithm object for another
       message by continuing with `update` and/or `digest` calls.
       
   To process a message with one call, don't use `update` and
   just call `digest(message)`.
   
   `reset()` clears the message from the algorithm so that
   the next `update` will start a new message. This is normally
   not needed as a new instance will start in a reset state, and after calling
   `finish()` the instance will also be reset.
   
See `digest.ceylon` in the `de.dlkw.ccrypto.examples` package.

## SHA-1

Implemented from the [Wikipedia entry](https://en.wikipedia.org/wiki/SHA-1).

### Usage

like SHA-256, use 

`value digest = sha1();`

See `digest.ceylon` in the `de.dlkw.ccrypto.examples` package.

## RSA

see `examples/de.dlkw.ccrypto.examples/signature.ceylon`

The JavaScript implementation of class `Whole` seems to be incorrect. While the
implemented PKCS #1 test vectors pass with the Java runtime, on JavaScript they fail,
running very, very, veeery long. I didn't investigate further yet. (Upcoming version 1.2.3 of `ceylon.Whole`
has supposedly been fixed to give the correct value for JavaScript. I didn't check, either.)

## Certificates

A first step was made to encode and decode X.509 certificates! You can generate certificates that can be parsed
by the Java keytool and you can generate self-signed certificates with the Java keytool that can be parsed and
signature-checked by this library. As UTCTime is not yet finished, you should use validity dates in or after 2050
so that the PKIX turnover date definitions in keytool cause a GeneralizedTime to be inserted into the certificate :-)

For example, generate a self-signed certificate (remember, only common name, organization, country are supported in the RDNs):

```bash
keytool -genkeypair -keyalg RSA -keysize 2048 -dname c=de -sigalg sha256WithRsa -keystore testgenkey.jks
keytool -exportcert -keystore testgenkey.jks -file testcert.der
```

then decode it and check the signature, see function test.de.dlkw.ccrypto.x509::readExtCert in test-source.

There's some (ugly) example code in the same file for creating a certificate.
