package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * sign JWS
 */
public interface JWTSigner {

    JWSObject sign(JWSHeader header, Payload payload) throws JOSERuntimeException;

    SignedJWT sign(JWSHeader header, JWTClaimsSet claimsSet) throws JOSERuntimeException;
}
