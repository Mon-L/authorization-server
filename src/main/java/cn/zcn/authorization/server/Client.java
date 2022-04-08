package cn.zcn.authorization.server;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;

import java.util.Date;
import java.util.Set;

/**
 * 客户端模型
 */
public interface Client {
    /**
     * 获取客户端密钥
     */
    String getClientSecret();

    /**
     * 获取客户端 ID
     */
    String getClientId();

    /**
     * 获取客户端身份验证方式
     */
    ClientAuthMethod getTokenEndpointAuthMethod();

    /**
     * 获取客户端公钥
     */
    JWKSet getJwks();

    /**
     * 获取客户端公钥的URL
     * 如果客户端没有配置Jwks，授权服务器可通过该地址获取客户端公钥，用于校验客户端的签名信息
     */
    String getJwksUri();

    /**
     * 客户端支持的response_type
     */
    Set<String> getResponseTypes();

    /**
     * 客户端支持的scopes
     */
    Set<String> getScope();

    Integer getDefaultMaxAge();

    /**
     * 客户端支持的grant_type
     */
    Set<String> getGrantTypes();

    /**
     * 客户端重定向URL
     */
    Set<String> getRedirectUris();

    /**
     * 授权请求中Request Object的签名算法
     */
    JWSAlgorithm getRequestObjectSigningAlg();

    /**
     * 令牌请求中客户端凭证签名算法
     */
    JWSAlgorithm getTokenEndpointAuthSigningAlg();

    /**
     * 客户端更新时间
     */
    Date getUpdatedAt();

    /**
     * 客户端创建时间
     */
    Date getCreatedAt();
}
