module itsdangerous.urlsafe;

import std.stdio;

import std.range;
import std.json;
import std.base64;
import std.digest.sha;
import std.zlib: compress, uncompress;
import std.algorithm.searching;

import itsdangerous.exc;
import itsdangerous.encoding;
import itsdangerous.dsigner;
import itsdangerous.serializer;
import itsdangerous.timed;

class URLSafeSerializerTemplate(SerializerType) : SerializerType {
    
    this(string secretKey, string salt = "itsdangerous"){
        super(secretKey, salt);
        //signer = makeSigner(salt);
    }

    override JSONValue loadPayload(string payload){
        string _json;
        bool decompress = false;
        if (payload.startsWith(".")){
            payload.popFront;
            decompress = true;
        }
        try{
            _json = base64Decode(payload);
        }catch (Base64Exception e){
            auto bpl = new BadPayload("Could not base64 decode the payload because of an exception");
            bpl.originalError = e.msg;
            throw bpl;
        }
        if (decompress){
            try{
                _json = cast(string)uncompress(_json);
            }catch (Exception e){
                auto bpl = new BadPayload("Could not zlib decompress the payload before decoding the payload");
                bpl.originalError = e.msg;
                throw bpl;
            }
        }
        return super.loadPayload(_json);
    }

    override string dumpPayload(JSONValue obj){
        string json = super.dumpPayload(obj);
        bool is_compressed = false;
        string compressed = cast(string)compress(json);
        const jlen = json.length; 
        if (compressed.length < (jlen - 1)){
            json = compressed;
            is_compressed = true;
        }
            
        string base64d = base64Encode(json);
        if (is_compressed)
            base64d = '.' ~ base64d;
        return base64d;
    }
}

alias URLSafeSerializer = URLSafeSerializerTemplate!(Serializer!(Signer!(SHA1, SHA1)));
alias URLSafeTimedSerializer = URLSafeSerializerTemplate!(TimedSerializer!(TimestampSigner!(SHA1, SHA1)));