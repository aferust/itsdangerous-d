module itsdangerous.serializer;

import std.stdio;
import std.file;
import std.json;
import std.typecons;

import itsdangerous.exc;

class Serializer(SignerType) {

    this(string secretKey, string salt = "itsdangerous"){
        this.secretKey = secretKey;
        this.salt = salt;
        //signer = makeSigner(salt);
    }

    string secretKey;
    string salt;
    SignerType signer;

    SignerType makeSigner(string salt = null){
        /+Creates a new instance of the signer to be used. The default
        implementation uses the :class:`.Signer` base class.
        +/
        if(salt is null)
            salt = this.salt;
        return new SignerType(secretKey, salt);
    }

    JSONValue loadPayload(string payload){
        try{
            return parseJSON(payload);
        } catch (Exception exc) {
            auto bpl = new BadPayload("Could not load the payload because an exception\n
                                        occurred on unserializing the data.");
            bpl.originalError = exc.msg;
            throw bpl;
        }
    }

    string dumpPayload(JSONValue obj){
        return obj.toJSON;
    }

    string dumps(JSONValue obj, string salt = null){
        /+ Returns a signed string serialized with the internal
        serializer.
        +/
        auto payload = dumpPayload(obj);
        string rv = makeSigner(salt).sign(payload);
        return rv;
    }

    void dump(JSONValue obj, File f, string salt = null){
        /+Like :meth:`dumps` but dumps into a file. The file handle has
        to be compatible with what the internal serializer expects.
        +/
        f.write(dumps(obj, salt));
    }

    JSONValue loads(string s, string salt = null, int maxAge = 0, int *tstamp = null){ // multiple signers are not supported yet.
        /+ Reverse of :meth:`dumps`. Raises :exc:`.BadSignature` if the
        signature validation fails.
        +/
        try{
            return loadPayload(signer.unsign(s));
        } catch (BadSignature ex) {
            throw new BadSignature(ex.msg);
        }
    }

    JSONValue load(string fileName, string salt = null){
        /+Like :meth:`loads` but loads from a file.+/
        return loads(readText(fileName), salt);
    }

    auto loadsUnsafe(string s, string salt = null){
        return _loadsUnsafeImpl(s, salt);
    }

    auto _loadsUnsafeImpl(string s, string salt = null){
        JSONValue emptyJson;
        try{
            return tuple(true, loads(s, salt));
        } catch (BadSignature ex) {
            if(ex.payload is null)
                return tuple(false, emptyJson);
            try{
                return tuple(false, loadPayload(ex.payload));
            } catch (BadPayload ex2) {
                return tuple(false, emptyJson);
            }
        }
    }

    auto loadUnsafe(string fileName){
        return loadsUnsafe(readText(fileName));
    }
}