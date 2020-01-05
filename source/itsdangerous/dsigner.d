module itsdangerous.dsigner;

import std.stdio;
import std.format;
import std.string: representation;
import std.digest.sha;
import std.digest.hmac;
import std.algorithm.searching;
import std.array;

import itsdangerous.encoding;
import itsdangerous.exc;

bool constantTimeCompare(string val1, string val2){ // not sure if we need this in D
    /*Return ``True`` if the two strings are equal, ``False``
    otherwise.
    */
    const len_eq = val1.length == val2.length;
    int result;
    string left;
    if (len_eq){
        result = 0;
        left = val1;
    } else {
        result = 1;
        left = val2;
    }
    import std.range: zip;
    foreach (x, y; zip(cast(ubyte[])left, cast(ubyte[])val2))
        result |= x ^ y;
    return result == 0;
}

interface SigningAlgorithm {
    /+Subclasses must implement :meth:`getSignature` to provide
    signature generation functionality.
    +/
	string getSignature(ubyte[] key, string value);
    bool verifySignature(ubyte[] key, string value, string sig);
}

class NoneAlgorithm: SigningAlgorithm {
    string getSignature(ubyte[] key, string value){
        return "";
    }

    bool verifySignature(ubyte[] key, string value, string sig){
        return true;
    }
}

class HMACAlgorithm(DigestMethod): SigningAlgorithm {

    string getSignature(ubyte[] key, string value){
		auto hmac = HMAC!DigestMethod(key);
        ubyte[] hash = hmac.put(value.representation).finish.dup;
		return cast(string)hash;
    }
        
    bool verifySignature(ubyte[] key, string value, string sig){
        /+Verifies the given signature matches the expected
        signature.
        +/
        //return sig == getSignature(key, value) ;
		return constantTimeCompare(sig, getSignature(key, value));
    }    
}

class Signer(DigestMethod, AlgDigestMethod) {

    this(string secretKey,
        string salt = null,
        char sep = '.',
        string keyDerivation = "django-concat"
            ){
        
        if(salt is null)
            this.salt = "itsdangerous.Signer";
        else
            this.salt = salt;
        
        if(canFind(BASE64_ALPHABET, sep))
            throw new Exception("The given separator cannot be used because it may be\n
                contained in the signature itself. Alphanumeric\n
                characters and `-_=` must not be used.");
        this.secretKey = secretKey;
        this.sep = sep;
        this.keyDerivation = keyDerivation;
		
        digester = new WrapperDigest!DigestMethod();
		algorithm = new HMACAlgorithm!AlgDigestMethod();
    }

    char sep;
    
    private {
        string secretKey;
        SigningAlgorithm algorithm;
        string salt;
        string keyDerivation;
        WrapperDigest!DigestMethod digester;
        
    }

    void setAlgorithm(SigningAlgorithm alg){
        this.algorithm = alg;
    }

    SigningAlgorithm getAlgorithm(){
        return this.algorithm;
    }

    final ubyte[] deriveKey(){
        /+This method is called to derive the key. The default key
        derivation choices can be overridden here. Key derivation is not
        intended to be used as a security method to make a complex key
        out of a short password. Instead you should use large random
        secret keys.
        +/
		
        if(keyDerivation == "concat"){
            digester.put(salt.representation);
            digester.put(secretKey.representation);
            return digester.finish();
        }
        else if (keyDerivation == "django-concat"){
            
            digester.put(salt.representation);
            digester.put("signer".representation);
            digester.put(secretKey.representation);
            
            //digester.put(salt.representation ~ "signer".representation ~ secretKey.representation);
            return digester.finish();
        }
        else if (keyDerivation == "hmac")
            return salt.representation.hmac!DigestMethod(secretKey.representation).dup;
        else if (keyDerivation == "none")
            return secretKey.representation.dup;
        else
            throw new Exception("Unknown key derivation method");
		
    }

	final string getSignature(string value){
        /+Returns the signature for the given value.+/
        ubyte[] key = deriveKey();
        string sig = algorithm.getSignature(key, value);
        return base64Encode(sig);
	}

	string sign(string value){
        /+Signs the given string.+/
        return value ~ sep ~ getSignature(value);
	}

	final bool verifySignature(string value, string sig){
        /+Verifies the signature for the given value.+/
        ubyte[] key = deriveKey();
		string decoded;
        try{
            decoded = base64Decode(sig);
        } catch (Exception exc) {
            return false;
		}
        return algorithm.verifySignature(key, value, decoded);
	}

    string unsign(string signedValue, int maxAge = 0, int* tstamp = null){
        /+ Unsigns the given string. +/
        if(!canFind(signedValue, sep))
            throw new BadSignature(format("No %c found in value", sep));
        immutable arr = signedValue.rsplit(sep);
        auto value = arr[0];
        auto sig = arr[1];
        if (verifySignature(value, sig))
            return value;
        throw new BadSignature(format("Signature %s does not match", sig), value);
    }

    bool validate(string signedValue){
        /+Only validates the given signed value. Returns ``True`` if
        the signature exists and is valid.
        +/
        try{
            unsign(signedValue);
            return true;
        } catch (BadSignature ex) {
            return false;
		}
    }
}