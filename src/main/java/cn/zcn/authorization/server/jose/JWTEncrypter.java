package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * encrypt JWE
 */
public interface JWTEncrypter {

    JWEObject encrypt(JWEHeader header, Payload payload) throws JOSERuntimeException;

    EncryptedJWT encrypt(JWEHeader header, JWTClaimsSet claimsSet) throws JOSERuntimeException;
}
