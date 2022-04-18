package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.Client;
import com.nimbusds.jose.JWSAlgorithm;

/**
 * 通过该接口提供客户端验签、客户端加密功能
 */
public interface ClientJOSEService {

    /**
     * 获取客户端对应对验签接口。
     * <p>
     * 客户端有两种加签方式：
     * 1. client secret 作为密钥，使用 HMAC 算法进行签名。
     * 2. 利用公私密钥，使用 RSA、ECDSA 算法进行签名。
     *
     * @param client 客户端
     * @param alg    签名算法
     * @return 验签接口
     */
    JWTVerifier getVerifier(Client client, JWSAlgorithm alg);

    /**
     * 获取客户端对应的加密接口。
     *
     * @param client 客户端
     * @return 加密接口
     */
    JWTEncrypter getEncrypter(Client client);
}
