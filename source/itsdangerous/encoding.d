module itsdangerous.encoding;

import std.base64: Base64URLNoPadding, Base64Exception;
import std.conv;
import std.array;
import std.encoding;
import std.string: representation;

import itsdangerous.exc;

__gshared immutable string BASE64_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=";

string base64Encode(T = string)(T s){
    static if (is(T == string)){
        return Base64URLNoPadding.encode(s.representation);
    } else
    static if (is(T == ubyte[])) {
        return Base64URLNoPadding.encode(s);
    }
    
}

string base64Decode(string s){
    try{
        return cast(string)Base64URLNoPadding.decode(s);
    } catch (Base64Exception ex) {
        throw new BadData("Invalid base64-encoded data: " ~ ex.msg);
    }
}

ubyte[] intToBytes(int n){
    ubyte[4] bytes;

    bytes[0] = (n >> 24) & 0xFF;
    bytes[1] = (n >> 16) & 0xFF;
    bytes[2] = (n >> 8) & 0xFF;
    bytes[3] = n & 0xFF;

    return bytes.dup;
}

int bytesToInt(ubyte[] bytes){
    return ((bytes[0] & 0xFF) << 24) + ((bytes[1] & 0xFF ) << 16) + ((bytes[2] & 0xFF ) << 8) + (bytes[3] & 0xFF);
}

auto rsplit(string str, char sep){ // emulating behaviour of python rsplit
    auto arr = str.split(sep);
    if(arr.length == 2)
        return arr;
    else if (arr.length == 3){
        auto last = arr[$-1];
        arr.popBack();
        return [arr[0] ~ '.' ~ arr[1], last];
    } else {
        throw new Exception("Unexpected signature: more than 3 elements!");
    }
}

unittest {
    assert(intToBytes(1577992918) == [94, 14, 66, 214]);
    assert(bytesToInt(intToBytes(1577992918)) == 1577992918);
}
