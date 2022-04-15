package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.JWSObject;

/**
 * verify JWS
 */
public interface JWTVerifier {

    boolean verify(JWSObject jwt) throws JOSERuntimeException;
}
