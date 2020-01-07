module itsdangerous.jws;

import std.stdio;
import std.conv;
import std.typecons;
import std.format;
import std.algorithm.searching;
import std.array;
import std.digest.sha;
import std.json;
import std.datetime;
import std.datetime.systime;

import itsdangerous.serializer;
import itsdangerous.encoding;
import itsdangerous.dsigner;
import itsdangerous.exc;

class JSONWebSignatureSerializer(DigestMethod, SignerType) : Serializer!SignerType {
    /+ for DigestMethod use SHA256, SHA384, SHA512
    SHA512 should be considered as default
     +/

    this(string secretKey, string salt = null){
        super(secretKey, salt);
    }
    
    Tuple!(JSONValue, JSONValue) loadPayloadWithHeader(string payload){

        if(!canFind(payload, '.'))
            throw new BadPayload("No \".\" found in value");
        
        auto arr = payload.split(".");
        
        string base64dHeader = arr[0];
        string base64dPayload = arr[1];
        
        string jsonHeader, jsonPayload;
        try{
            jsonHeader = base64Decode(base64dHeader);
        } catch (BadData e){
            throw new BadHeader(format("Could not base64 decode the header because of an exception: %s", e.msg));
        }

        try{
            jsonPayload = base64Decode(base64dPayload);
        } catch (BadData e){
            throw new BadPayload(format("Could not base64 decode the payload because of an exception: %s", e.msg));
        }

        JSONValue headerStruct;
        try{
            headerStruct = this.Serializer.loadPayload(jsonHeader);
        } catch (BadData e){
            throw new BadHeader(format("Could not unserialize header because it was malformed: %s", e.msg));
        }

        JSONValue payloadStruct = this.Serializer.loadPayload(jsonPayload);
        return tuple(headerStruct, payloadStruct);
    }

    override JSONValue loadPayload(string payload){

        if(!canFind(payload, '.'))
            throw new BadPayload("No \".\" found in value");
        
        auto arr = payload.split(".");
        
        string base64dHeader = arr[0];
        string base64dPayload = arr[1];
        
        string jsonHeader, jsonPayload;
        try{
            jsonHeader = base64Decode(base64dHeader);
        } catch (BadData e){
            throw new BadHeader(format("Could not base64 decode the header because of an exception: %s", e.msg));
        }

        try{
            jsonPayload = base64Decode(base64dPayload);
        } catch (BadData e){
            throw new BadPayload(format("Could not base64 decode the payload because of an exception: %s", e.msg));
        }

        JSONValue headerStruct;
        try{
            headerStruct = this.Serializer.loadPayload(jsonHeader);
        } catch (BadData e){
            throw new BadHeader(format("Could not unserialize header because it was malformed: %s", e.msg));
        }

        JSONValue payloadStruct = this.Serializer.loadPayload(jsonPayload);
        return payloadStruct;
    }

    string dumpPayload(JSONValue header, JSONValue obj){
        string base64dHeader = base64Encode(
            toJSON(header)
        );
        string base64dPayload = base64Encode(
            toJSON(obj)
        );
        return base64dHeader ~ '.' ~ base64dPayload;
    }

    string digestName(){
        string digname;
        static if (is(DigestMethod == SHA!(1024u, 512u))){
            digname = "HS512";
        }
        else static if (is(DigestMethod == SHA!(1024u, 384u))){
            digname = "HS384";
        }
        else static if (is(DigestMethod == SHA!(512u, 256u))){
            digname = "HS256";
        }
        else {
            static assert( false, "unsupported digest type!");
        }
        return digname;
    }

    auto makeSignerForTJWT(string salt = null){
        string fsalt;
        if (salt is null)
            fsalt = this.salt;
        else
            fsalt = salt;   
        
        auto key_derivation = (fsalt is null)?"none":"django-concat";
        
        auto sigAlg = new HMACAlgorithm!SHA512();
        
        auto _signer = new Signer!(SHA1, SHA512)(
            this.Serializer.secretKey,
            fsalt,
            '.',
            "none"
        );

        _signer.setAlgorithm(sigAlg);
        return _signer;
    }

    JSONValue makeHeader(JSONValue header){
        header["alg"] = digestName();
        return header;
    }

    final string dumps(JSONValue obj, string salt = null, JSONValue headerFields = null){
        /+Like :meth:`.Serializer.dumps` but creates a JSON Web
        Signature. It also allows for specifying additional fields to be
        included in the JWS header.
        +/
        JSONValue header = makeHeader(headerFields);
        auto signer = makeSignerForTJWT(salt);
        //signer.writeln;
        //signer.getAlgorithm.writeln;
        auto tmp = dumpPayload(header, obj);
        return signer.sign(tmp);
    }

    override JSONValue loads(string s, string salt = null, int maxAge = 0, int *tstamp = null){
        /+Reverse of :meth:`dumps`. If requested via ``return_header``
        it will return a tuple of payload and header.
        +/
        auto signer = makeSignerForTJWT(salt);
        auto arr = loadPayloadWithHeader(
            signer.unsign(s)
        );
        auto header = arr[0];
        auto payload = arr[1];

        if (header["alg"].str != digestName())
            throw new BadHeader(format("Algorithm mismatch %s != %s", header["alg"], digestName()));

        return payload;
    }

    Tuple!(JSONValue, JSONValue) loadsWithHeader(string s, string salt = null){
        /+Reverse of :meth:`dumps`. If requested via ``return_header``
        it will return a tuple of payload and header.
        +/
        auto signer = makeSignerForTJWT(salt);
        auto arr = loadPayloadWithHeader(signer.unsign(s));
        auto header = arr[0];
        auto payload = arr[1];

        if (header["alg"].str != digestName())
            throw new BadHeader(format("Algorithm mismatch %s != %s", header["alg"], digestName()));

        return tuple(payload, header);
    }
}

enum DEFAULT_EXPIRES_IN = 3600;

class TimedJSONWebSignatureSerializer(DigestMethod, SignerType) : 
    JSONWebSignatureSerializer!(DigestMethod, SignerType) {
        
    this(string secretKey, int expiresIn = DEFAULT_EXPIRES_IN, string salt = "itsdangerous.Signer"){
        super(secretKey, salt);
        this.expiresIn = expiresIn;
    }

    int expiresIn;

    int now(){
        import std.datetime.systime;
        return cast(int)Clock.currTime.toUnixTime();
    }
    
    override JSONValue makeHeader(JSONValue header){
        header["alg"] = digestName();
        const iat = now();
        const exp = iat + expiresIn;

        import std.conv;
        header["iat"] = iat;
        header["exp"] = exp;

        return header;
    }

    override JSONValue loads(string s, string salt = null, int maxAge = 0, int *tstamp = null){
        auto tup = this.JSONWebSignatureSerializer.loadsWithHeader(s, salt);
        JSONValue payload = tup[0];
        JSONValue header = tup[1];

        try{
            const exp = ("exp" in header);
        }catch(JSONException ex){
            auto excn = new BadHeader("Missing expiry date");
            excn.payload = payload.toJSON;
            throw excn;
        }
        
        auto int_date_error = new BadHeader("Expiry date is not an IntDate");
        
        try{
            header["exp"] = header["exp"].integer;
        } catch (Exception ex){
            throw int_date_error;
        }

        if (header["exp"].integer < 0)
            throw int_date_error;
        
        if (header["exp"].integer < now())
            throw new SignatureExpired(format("Signature expired: date signed: %s", getIssueDate(header)));
        return payload;
    }

    override Tuple!(JSONValue, JSONValue) loadsWithHeader(string s, string salt = null){
        auto tup = this.JSONWebSignatureSerializer.loadsWithHeader(s, salt);
        JSONValue payload = tup[0];
        JSONValue header = tup[1];
        
        try{
            const exp = ("exp" in header);
        }catch(JSONException ex){
            auto excn = new BadHeader("Missing expiry date!");
            excn.payload = payload.toJSON;
            throw excn;
        }
        
        auto int_date_error = new BadHeader("Expiry date is not an IntDate!");
        
        try{
            header["exp"] = header["exp"].integer;
        } catch (JSONException ex){
            throw int_date_error;
        }

        if (header["exp"].integer < 0)
            throw int_date_error;
        
        if (header["exp"].integer < now()){
            auto excn = new SignatureExpired(format("Signature expired: date signed: %s", getIssueDate(header)));
            excn.payload = payload.toJSON;
            throw excn;
        }
            
        return tuple(payload, header);
    }

    string getIssueDate(JSONValue header){
        int rv = header["iat"].integer.to!int;

        return SysTime.fromUnixTime(rv).toString;
    }

}