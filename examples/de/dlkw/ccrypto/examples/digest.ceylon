import de.dlkw.ccrypto.svc {
    sha256,
    sha1
}
import import ceylon.file {
    Path
}
import ceylon.buffer.base {
    base16String
}

"Illustrates the use of SHA-256."
shared void runDigestSha256() {
    value digester = sha256();
    digester.update({#61.byte, #62.byte});
    Byte[] digest = digester.digest({#63.byte});
}

"Given a file, return its sha256sum in hex form."
String? sha256FileHex(Path filePath) {
    value digester = sha256();
    Byte[] sha256sum;
    if (is File file = filePath.resource) {
        try (reader = file.Reader()) {
            Integer bufferSize = 64 * 1024;
            Integer remainingSize = file.size % bufferSize;
            variable Integer parts = file.size / bufferSize;
            variable Byte[] bytes;
            while (parts > 0) {
                bytes = reader.readBytes(bufferSize);
                digester.update(bytes);
                parts--;
            }
            Byte[] remainder = reader.readBytes(remainingSize);
            sha256sum = digester.digest(remainder);
        }
        return base16String.encode(sha256sum);
    } else {
        return null;
    }
}

"Illustrates the use of SHA-1."
shared void runDigestSha1() {
    value digester = sha1();
    digester.update({#61.byte, #62.byte});
    digester.update({#63.byte});
    Byte[] digest = digester.digest();
}
