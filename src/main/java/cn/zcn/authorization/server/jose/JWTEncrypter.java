package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * 对 JWT 进行加密，加密对形式为 JWE
 */
public interface JWTEncrypter {

    /**
     * 对 JWT 进行加密。可对 Payload 为普通字符串、字节数组等形式的 JWT 进行加密
     *
     * @param header  JWE Header
     * @param payload JWE Payload
     * @return 已加密对 JWE
     * @throws JOSERuntimeException 加密异常
     */
    JWEObject encrypt(JWEHeader header, Payload payload) throws JOSERuntimeException;

    /**
     * 对 JWT 进行加密。可对 Payload 为 JSON 的 JWT 进行加密
     *
     * @param header    JWE Header
     * @param claimsSet JWE Payload
     * @return 已加密的 JWE
     * @throws JOSERuntimeException 加密异常
     */
    EncryptedJWT encrypt(JWEHeader header, JWTClaimsSet claimsSet) throws JOSERuntimeException;
}
