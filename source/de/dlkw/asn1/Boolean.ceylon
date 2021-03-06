"Represents an ASN.1 BOOLEAN value."
shared class Asn1Boolean(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
        extends Asn1Value<Boolean>(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentOctetsOffset;
    Boolean violatesDer;
    Boolean valu;

    shared actual String asn1ValueString => if (val) then "TRUE" else "FALSE";
    shared actual Tag defaultTag => UniversalTag.boolean;
}

"Creates an Asn1Boolean."
shared Asn1Boolean asn1Boolean(val, tag = UniversalTag.boolean)
{
    "The boolean value to represent as ASN.1 value."
    Boolean val;
    
    "The (IMPLICIT) tag that should be used in the encoding.
     If omitted, the standard tag of class UNIVERSAL is used."
    Tag tag;
    
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    
    return Asn1Boolean(identityOctets.withTrailing(2.byte).withTrailing(if (val) then #ff.byte else #00.byte), identityInfo, lengthOctetsOffset, lengthOctetsOffset + 1, false, val);
}

"Decodes BOOLEAN. Returns an error if the length octets encode any value
 other than 1"
shared class Asn1BooleanDecoder(Tag tag = UniversalTag.boolean)
        extends Decoder<Asn1Boolean>(tag)
{
    shared actual [Asn1Boolean, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        if (length != 1) {
            return DecodingError(offset - 1, "BOOLEAN must have length 1");
        }
        
        value contentsOctet = input[offset];
        if (is Null contentsOctet) {
            return DecodingError(offset, "end of input");
        }
        
        violatesDer ||= (contentsOctet != 0.byte && contentsOctet != #ff.byte);
        value booleanValue = contentsOctet != 0.byte;

        return [Asn1Boolean(input[identityOctetsOffset .. offset - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, lengthOctetsOffset - identityOctetsOffset + 1, false, booleanValue), offset + length];
    }
}