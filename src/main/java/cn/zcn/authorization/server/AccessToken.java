package cn.zcn.authorization.server;

import java.util.Date;
import java.util.Map;
import java.util.Set;

/**
 * 访问令牌接口定义
 */
public interface AccessToken {

    /**
     * 获取访问令牌的所属客户端的 Client ID，对应 {@link Client#getClientId()} 的值
     *
     * @return 访问令牌所属客户端的 Client ID
     */
    String getClientId();

    /**
     * 返回访问令牌的类型
     *
     * @return 访问令牌类型
     */
    TokenType getTokenType();

    /**
     * 返回访问令牌的值。客户端将使用该值访问受保护的资源
     *
     * @return 访问令牌
     */
    String getValue();

    /**
     * 返回访问令牌关联的所有 scope
     *
     * @return scope 列表。该列表的长度可为零
     */
    Set<String> getScope();

    /**
     * 返回访问令牌关联的刷新令牌
     *
     * @return 刷新令牌；如果访问令牌未关联刷新令牌则为 null
     */
    RefreshToken getRefreshToken();

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
     * 访问令牌的有效时间，单位为秒。
     * 例如，返回结果为3000，表示该令牌将在3000秒后过期
     *
     * @return 0，令牌已过期；> 0，令牌将在 N 秒后过期
     */
    int getExpiresIn();

    /**
     * 访问令牌过期时间，表示访问令牌在该时候之后将无法使用
     *
     * @return 访问令牌过期时间
     */
    Date getExpiration();

    /**
     * 访问令牌的额外信息
     *
     * @return 访问令牌额外信息
     */
    Map<String, Object> getAdditionalInformation();
}
