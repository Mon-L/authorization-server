package cn.zcn.authorization.server.endpoint;

import cn.zcn.authorization.server.ServerConfig;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.Map;

public class AuthorizationEndpoint {

    @RequestMapping(value = ServerConfig.AUTHORIZATION_ENDPOINT, method = RequestMethod.GET)
    public ModelAndView authorize(Map<String, Object> model, Principal principal, HttpServletRequest request, HttpServletResponse response) {
        return null;
    }
}
