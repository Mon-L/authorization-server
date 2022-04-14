package cn.zcn.authorization.server;

public interface TokenService {

    /**
     * 为客户端颁发用户同意访问令牌。用于授权码模式、简化模式、密码模式
     *
     * @param client         客户端
     * @param authentication
     * @return 访问令牌
     */
    AccessToken issueTokenWithUser(Client client, OAuth2Authentication authentication);

    /**
     * 为客户端颁发客户端访问令牌。用于客户端模式
     *
     * @param client         客户端
     * @param authentication
     * @return 访问令牌
     */
    AccessToken issueTokenWithClient(Client client, OAuth2Authentication authentication);

    /**
     * 处理令牌刷新请求. 只有在授权码模式、密码模式下授权服务器才会颁发刷新令牌
     *
     * @param client         客户端
     * @param authentication
     * @return 新的访问令牌
     */
    AccessToken refreshToken(Client client, OAuth2Authentication authentication);

    /**
     * 通过访问令牌获取用户凭证
     *
     * @param accessToken 访问令牌
     * @return {@link OAuth2Authentication} 用户授权信息
     */
    OAuth2Authentication loadAuthenticationWithAccessToken(String accessToken);

    /**
     * 通过刷新令牌获取用户凭证
     *
     * @param refreshToken 刷新令牌
     * @return {@link OAuth2Authentication} 用户授权信息
     */
    OAuth2Authentication loadAuthenticationWithRefreshToken(String refreshToken);
}
