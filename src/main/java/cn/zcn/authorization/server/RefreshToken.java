package cn.zcn.authorization.server;

import java.util.Date;
import java.util.Set;

public interface RefreshToken {
    /**
     * 获取刷新令牌的所属客户端的 Client ID，对应 {@link Client#getClientId()} 的值
     *
     * @return 刷新令牌所属客户端的 Client ID
     */
    String getClientId();

    /**
     * 返回刷新令牌的类型
     *
     * @return 刷新令牌类型
     */
    TokenType getTokenType();

    /**
     * 返回刷新令牌的值。客户端将使用该值访问受保护的资源
     *
     * @return 刷新令牌
     */
    String getValue();

    /**
     * 返回刷新令牌关联的所有 scope
     *
     * @return scope 列表。该列表的长度可为零
     */
    Set<String> getScope();

    /**
     * 令牌创建时间
     *
     * @return 创建时间
     */
    Date getCreatedAt();

    /**
     * 判断令牌是否过期
     *
     * @return ture，未过期；false，已过期
     */
    boolean isExpired();

    /**
     * 刷新令牌的有效时间，单位为秒。
     * 例如，返回结果为3000，表示该令牌将在3000秒后过期
     *
     * @return 0，令牌已过期；> 0，令牌将在 N 秒后过期
     */
    int getExpiresIn();

    /**
     * 刷新令牌过期时间，表示刷新令牌在该时候之后将无法使用
     *
     * @return 刷新令牌过期时间
     */
    Date getExpiration();
}
