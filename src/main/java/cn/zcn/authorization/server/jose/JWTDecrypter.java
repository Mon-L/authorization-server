package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.JWEObject;

/**
 * decrypt JWE
 */
public interface JWTDecrypter {

    void decrypt(JWEObject jwt) throws JOSERuntimeException;
}
