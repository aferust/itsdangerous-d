module itsdangerous.exc;

import std.datetime.date;

class BadData : Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) {
        super(msg, file, line);
    }
}

class BadSignature : BadData {
    /+ Raised if a signature does not match. +/
    string payload;

    this(string msg, string file = __FILE__, size_t line = __LINE__, string payload = null) {
        super(msg, file, line);
        /+
        #: The payload that failed the signature test. In some
        #: situations you might still want to inspect this, even if
        #: you know it was tampered with.
        +/
        this.payload = payload;
    }
}

class BadTimeSignature : BadSignature {
    /+
    Raised if a time-based signature is invalid. This is a subclass
    of :class:`BadSignature`.
    +/
    string dateSignedStr;
    this(string msg, string file = __FILE__, size_t line = __LINE__,
        string payload = null, string dateSignedStr = null) {
        super(msg, file, line, payload);
        /+
        #: If the signature expired this exposes the date of when the
        #: signature was created. This can be helpful in order to
        #: tell the user how long a link has been gone stale.
        #:
        +/
        this.dateSignedStr = dateSignedStr;
    }
}

class SignatureExpired : BadTimeSignature {
    /+Raised if a signature timestamp is older than ``max_age``. This
    is a subclass of :exc:`BadTimeSignature`.
    +/
    this(string msg, string file = __FILE__, size_t line = __LINE__,
        string payload = null, string dateSignedStr = null) {
        super(msg, file, line, payload, dateSignedStr);
    }
}

class BadHeader : BadSignature {
    /+Raised if a signed header is invalid in some form. This only
    happens for serializers that have a header that goes with the
    signature.
    +/
    string originalError;
    this(string msg, string file = __FILE__, size_t line = __LINE__,
        string payload = null, string header=null, string originalError = null ){
        super(msg, file, line, payload);
        /+
        #: If the header is actually available but just malformed it
        #: might be stored here.
        self.header = header

        #: If available, the error that indicates why the payload was
        #: not valid. This might be ``None``.
        +/
        this.originalError = originalError;
    }
}

class BadPayload : BadData {
    /+Raised if a payload is invalid. This could happen if the payload
    is loaded despite an invalid signature, or if there is a mismatch
    between the serializer and deserializer. The original exception
    that occurred during loading is stored on as :attr:`original_error`.
    +/
    string originalError;
    this(string msg, string file = __FILE__, size_t line = __LINE__, string originalError = null){
        super(msg);
        /+
        #: If available, the error that indicates why the payload was
        #: not valid. This might be ``None``.
        self.original_error = original_error
        +/
        this.originalError = originalError;
    }
}