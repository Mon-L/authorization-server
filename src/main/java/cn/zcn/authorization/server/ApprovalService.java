package cn.zcn.authorization.server;

import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * 处理用户同意接口
 */
public interface ApprovalService {

    /**
     * 跳转至用户同意页面。
     * 在某些情况下，你需要在跳转至用户同意界面之前保存授权请求参数至 session 或其他缓存中。
     *
     * @param authorizationRequest 当前授权请求
     * @param client               请求授权的客户端
     * @return 用户同意页面
     */
    ModelAndView redirectForApproval(Client client, AuthorizationRequest authorizationRequest);

    /**
     * 用于用户同意授权或拒绝授权后，用于加载跳转到授权页面前的授权请求参数。也许你需要从  session 或 其他缓存中加载授权请求参数。
     *
     * @param httpServletRequest 当前http request
     * @param approvalParameters 用户同意参数
     * @return {@link AuthorizationRequest} 找到了跳转用户同意页面之前保存的授权请求； null 没找到跳转用户同意页面之前保存的授权请求
     */
    AuthorizationRequest loadAuthorizationRequestAfterApproveOrDeny(HttpServletRequest httpServletRequest, Map<String, String> approvalParameters);

    /**
     * 检查用户是否同意授权给客户端。需要校验用户是否同意了客户端请求授权的所有权限。
     *
     * @param authentication       用户
     * @param authorizationRequest 授权请求
     * @return true, 客户端请求授权的所有权限用户都同意了；false, 用户未同意或部分同意客户端请求授权的权限
     */
    boolean isAllScopeApproved(Authentication authentication, AuthorizationRequest authorizationRequest);

    /**
     * 更新用户授权信息
     *
     * @param authentication       用户
     * @param authorizationRequest 原始授权请求参数
     * @param approvalParameters   用户同意参数
     * @return true，用户同意授权；false，用户拒绝授权
     */
    boolean updateApproveOrDeny(Authentication authentication, AuthorizationRequest authorizationRequest, Map<String, String> approvalParameters);
}
