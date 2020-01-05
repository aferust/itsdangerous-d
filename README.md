# itsdangerous-d

D port of the [itsdangerous](https://github.com/pallets/itsdangerous) Python library.

## Disclaimer
Although initial tests are OK, more tests are needed. Please do not use for production yet. Or please make your own tests and make PRs if needed.

## Some example usages
```d
import std.stdio;

import itsdangerous;

void main(){
    // Signer
	string secretkey = "hello";
    
    auto signer = new Signer!(SHA1, SHA1)(secretkey);
	string signature = signer.sign("this is a test");
	assert(signature == "this is a test.hgGT0Zoara4L13FX3_xm-xmfa_0");
    
    assert(signer.verifySignature("this is a test", "hgGT0Zoara4L13FX3_xm-xmfa_0") == true);
    assert(signer.unsign("this is a test.hgGT0Zoara4L13FX3_xm-xmfa_0") == "this is a test");
    
    // TimedJSONWebSignatureSerializer
    int expiresIn = 3600;

    JSONValue obj;
    obj["a"] = 13;
	obj["b"] = "test me";

    // below configuration is the default of Python version: s = TimedJSONWebSignatureSerializer(secretkey, expiresIn)
    // output token can be tested on https://jwt.io/

    auto tjwss = new TimedJSONWebSignatureSerializer!(SHA512, Signer!(SHA1, SHA512))(secretkey, expiresIn);

    auto ttoken = tjwss.dumps(obj); ttoken.writeln;
    
    try{
        tjwss.loadsWithHeader(
            "eyJhbGciOiJIUzUxMiIsImV4cCI6MTU3ODI1MjY2NSwiaWF0IjoxNTc4MjQ5MDY1fQ.eyJhIjoxMywiYiI6InRlc3QgbWUifQ.qqrNdREltv9-3khCBxd0BQI50gTNNLbjUcjVOdCR6arlBrVTx1NGAfpoqn_FHYl2bxFbyWEvPFCumfr_e_m-UA"
        ).writeln;
    } catch (SignatureExpired exp){
        writeln("signature expired!");
    } catch (BadSignature exp){
        writeln("Bad signature!");
    }
}
```
