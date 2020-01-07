module itsdangerous.timed;

import std.stdio;
import std.datetime;
import std.datetime.systime;
import std.algorithm.searching;
import std.format;
import std.json;

import itsdangerous.dsigner;
import itsdangerous.encoding;
import itsdangerous.serializer;
import itsdangerous.exc;

class TimestampSigner(DigestMethod, AlgDigestMethod) : Signer!(DigestMethod, AlgDigestMethod) {
    /+
    Works like the regular :class:`.Signer` but also records the time
    of the signing and can be used to expire signatures. The
    :meth:`unsign` method can raise :exc:`.SignatureExpired` if the
    unsigning failed because the signature is expired.
    +/
    this(string secretKey,
        string salt = "itsdangerous.Signer",
        char sep = '.',
        string keyDerivation = "django-concat"
            ){
        super(secretKey, salt, sep, keyDerivation);
    }

    final int getTimestamp(){
        /+Returns the current timestamp. The function must return an
        integer.
        +/
        return cast(int)Clock.currTime.toUnixTime();
    }

    final DateTime timestampToDatetime(int ts){
        /+
        Used to convert the timestamp from :meth:`get_timestamp` into
        a datetime object.
        +/
        return cast(DateTime)SysTime.fromUnixTime(ts);
    }

    override string sign(string value){
        /+ Signs the given string and also attaches time information. +/
        string timestamp = base64Encode!(ubyte[])(intToBytes(getTimestamp())); 
        string _value = value ~ sep ~ timestamp;
        return _value ~ sep ~ this.Signer.getSignature(_value);
    }

    override string unsign(string value, int maxAge = 0, int* tstamp = null){
        BadSignature sigError;
        string result;
        
        try {
            result = this.Signer.unsign(value);
        } catch (BadSignature ex) {
            sigError = new BadSignature("unsign method (of super class Signer) cannot unsign timed data!");
            result = "";
		}
        if(!canFind(result, sep)){
            if (sigError !is null)
                throw sigError;
            auto bts = new BadTimeSignature("timestamp missing");
            bts.payload = result;
            throw bts;
        }
        import std.array;
        auto arr = result.rsplit(sep);
        string _value = arr[0];
        string timestamp = arr[1];
        
        int timestampInt;
        try{
            timestampInt = bytesToInt(cast(ubyte[])base64Decode(timestamp));
        } catch (Exception ex) {
            throw new Exception("cannot convert bytes to int");
        }

        if (sigError !is null){
            auto bts = new BadTimeSignature(sigError.msg);
            bts.payload = _value;
            bts.dateSignedStr = timestamp;
            throw bts;
        }
            
        if(timestamp is null){
            auto bts = new BadTimeSignature("Malformed timestamp");
            bts.payload = _value;
            throw bts;
        }

        if (maxAge != 0){
            int age = getTimestamp() - timestampInt;
            if (age > maxAge){
                auto sigExpired = new SignatureExpired(format("Signature age %s > %s seconds", age, maxAge));
                sigExpired.payload = value;
                sigExpired.dateSignedStr = timestampToDatetime(timestampInt).toSimpleString;
                throw sigExpired;
            }
        }

        if(tstamp !is null)
            *tstamp = timestampInt;
        
        return _value;
    }

    final bool validate(string signedValue, int maxAge){
        /+ Only validates the given signed value. Returns ``True`` if
        the signature exists and is valid.+/
        try{
            unsign(signedValue, maxAge);
            return true;
        } catch (BadSignature ex) {
            return false;
        }
    }
}

class TimedSerializer(SignerType) : Serializer!SignerType {
    /*Uses :class:`TimestampSigner` instead of the default
    :class:`.Signer`.
    */
    
    this(string secretKey, string salt = "itsdangerous"){
        super(secretKey, salt);
    }

    override JSONValue loads(string s, string salt = null, int maxAge = 0, int *tstamp = null){
        /*Reverse of :meth:`dumps`, raises :exc:`.BadSignature` if the
        signature validation fails. If a ``max_age`` is provided it will
        ensure the signature is not older than that time in seconds. In
        case the signature is outdated, :exc:`.SignatureExpired` is
        raised. All arguments are forwarded to the signer's
        :meth:`~TimestampSigner.unsign` method.
        */
        Exception lastException = null;
        int timestamp;
        string base64d;
        if(signer is null)
            signer = makeSigner(this.salt);
        try{
            base64d = signer.unsign(s, maxAge, &timestamp);
            auto payload = loadPayload(base64d); 
            if (tstamp !is null){
                *tstamp = timestamp;
            }
            return payload;

        } catch (SignatureExpired ex){
            throw new SignatureExpired(ex.msg);
        } catch (BadTimeSignature ex3){
            lastException = new BadTimeSignature(ex3.msg);
        } catch (BadSignature ex2){
            lastException = new BadSignature(ex2.msg);
        }
        throw lastException;
    }

    /+ ?
    def loads_unsafe(self, s, max_age=None, salt=None):
        load_kwargs = {"max_age": max_age}
        load_payload_kwargs = {}
        return self._loads_unsafe_impl(s, salt, load_kwargs, load_payload_kwargs)
    +/
}