package cn.zcn.authorization.server;

public interface TokenService {

    /**
     * 为客户端颁发可访问用户受保护资源的访问令牌。用于授权码模式、简化模式、密码模式
     *
     * @param client         客户端
     * @param authentication 用户凭证
     * @return 访问令牌
     */
    AccessToken issueTokenBoundUser(Client client, OAuth2Authentication authentication);

    /**
     * 为客户端颁发客户端访问令牌。用于客户端模式
     *
     * @param client         客户端
     * @param authentication 客户端凭证
     * @return 访问令牌
     */
    AccessToken issueTokenBoundClient(Client client, OAuth2Authentication authentication);

    /**
     * 处理令牌刷新请求。只有在授权码模式、密码模式下授权服务器才会颁发刷新令牌
     *
     * @param client         客户端
     * @param authentication 用户凭证
     * @return 新的访问令牌
     */
    AccessToken refreshToken(Client client, OAuth2Authentication authentication);

    /**
     * 通过访问令牌获取绑定的用户凭证
     *
     * @param accessToken 访问令牌
     * @return {@link OAuth2Authentication} 用户凭证
     */
    OAuth2Authentication loadAuthenticationWithAccessToken(String accessToken);

    /**
     * 通过刷新令牌获取绑定的用户凭证
     *
     * @param refreshToken 刷新令牌
     * @return {@link OAuth2Authentication} 用户凭证
     */
    OAuth2Authentication loadAuthenticationWithRefreshToken(String refreshToken);
}
