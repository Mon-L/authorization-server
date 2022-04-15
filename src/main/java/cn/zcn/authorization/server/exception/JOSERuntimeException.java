package cn.zcn.authorization.server.exception;

public class JOSERuntimeException extends RuntimeException {
    public JOSERuntimeException(String msg) {
        super(msg);
    }

    public JOSERuntimeException(String msg, Throwable e) {
        super(msg, e);
    }
}
