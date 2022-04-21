package cn.zcn.authorization.server;

import cn.zcn.authorization.server.exception.OAuth2Exception;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Set;

/**
 * 在简化模式、授权码模式中处理用户同意的接口。
 */
public interface ApprovalService {

    /**
     * 跳转至用户同意页面。
     * 在某些情况下，也许你需要在跳转至用户同意界面之前保存授权请求参数到{@link javax.servlet.http.HttpSession} 、缓存、持久化数据库中。
     *
     * @param authorizationRequest 当前授权请求
     * @param client               请求授权的客户端
     * @return 用户同意页面
     */
    ModelAndView redirectForUserApproval(Client client, AuthorizationRequest authorizationRequest);

    /**
     * 校验用户是否之前已经同意过此客户端请求的所有权限，并且用户同意未过期
     *
     * @param authentication       用户
     * @param authorizationRequest 授权请求
     * @return true, 用户同意了客户端请求的所有权限；false, 用户未同意或部分同意了客户端请求权限
     */
    boolean isAlreadyApproved(Authentication authentication, AuthorizationRequest authorizationRequest);

    /**
     * 用于用户同意授权或拒绝授权后，获取授权请求参数。
     * 在某些情况下，也许你需要从{@link javax.servlet.http.HttpSession} 、缓存、持久化数据库中加载。
     *
     * @param httpServletRequest 当前 http request
     * @param approvalParameters 用户同意参数
     * @return {@link AuthorizationRequest} 获取授权请求； null, 没找到授权请求
     * @throws OAuth2Exception 异常
     */
    AuthorizationRequest loadAuthorizationRequestAfterUserApproval(HttpServletRequest httpServletRequest, Map<String, String> approvalParameters) throws OAuth2Exception;

    /**
     * 更新用户同意信息
     * <p>
     * 须使用{@link AuthorizationRequest#setScope(Set)}更新用户同意后的 scope。
     *
     * @param authentication       用户
     * @param authorizationRequest 授权请求参数
     * @param approvalParameters   用户同意参数
     * @return true, 用户同意授权；false,用户拒绝授权
     * @throws OAuth2Exception 异常
     */
    boolean updateApprovalOrDenying(Authentication authentication, AuthorizationRequest authorizationRequest, Map<String, String> approvalParameters);
}
