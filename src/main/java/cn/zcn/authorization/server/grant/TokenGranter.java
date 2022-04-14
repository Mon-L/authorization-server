package cn.zcn.authorization.server.grant;

import cn.zcn.authorization.server.AccessToken;
import cn.zcn.authorization.server.Client;
import cn.zcn.authorization.server.TokenRequest;
import cn.zcn.authorization.server.exception.OAuth2Exception;

/**
 * 令牌颁发器
 */
public interface TokenGranter {

    /**
     * 颁发访问令牌
     *
     * @param client       令牌请求方
     * @param tokenRequest 颁发请求
     * @return 访问令牌
     */
    AccessToken grant(Client client, TokenRequest tokenRequest) throws OAuth2Exception;

    /**
     * 判断该令牌颁发器是否能处理该颁发请求
     *
     * @param tokenRequest 颁发请求
     * @return ture, 可以处理；false,不能处理
     */
    boolean support(TokenRequest tokenRequest);
}
