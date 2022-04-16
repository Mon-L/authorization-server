package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.JWEObject;

/**
 * 解密 JWE
 */
public interface JWTDecrypter {

    /**
     * 解密 JWE
     *
     * @param jwe 待解密的 JWE
     * @throws JOSERuntimeException 解密异常
     */
    void decrypt(JWEObject jwe) throws JOSERuntimeException;
}
