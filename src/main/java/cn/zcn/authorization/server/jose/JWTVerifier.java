package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.JWSObject;

/**
 * 验证 JWS 签名
 */
public interface JWTVerifier {

    /**
     * 验证 JWS 的签名是否合法
     *
     * @param jws 待验签的 JWS
     * @return true, 签名合法；false,签名不合法
     * @throws JOSERuntimeException 验签异常
     */
    boolean verify(JWSObject jws) throws JOSERuntimeException;
}
