package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * 对 JWT 进行加签名
 */
public interface JWTSigner {

    /**
     * 对 JWT 进行签名。可对 Payload 为普通字符串、字节数组等形式的 JWT 进行签名
     *
     * @param header  JWS Header
     * @param payload JWS Payload
     * @return 已签名的 JWS
     * @throws JOSERuntimeException 签名异常
     */
    JWSObject sign(JWSHeader header, Payload payload) throws JOSERuntimeException;

    /**
     * 对 JWT 进行签名。对 Payload 为 JSON 的 JWT 进行签名
     *
     * @param header    JWS Header
     * @param claimsSet JWS Payload
     * @return 已签名的 JWS
     * @throws JOSERuntimeException 签名异常
     */
    SignedJWT sign(JWSHeader header, JWTClaimsSet claimsSet) throws JOSERuntimeException;
}
