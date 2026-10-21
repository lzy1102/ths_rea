class HevoError(Exception):
    pass

class AuthError(HevoError):
    pass

class ProtocolError(HevoError):
    pass

class HxError(HevoError):
    pass
