package cn.zcn.authorization.server.endpoint;

import cn.zcn.authorization.server.ServerConfig;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.Map;

public class TokenEndpoint {

    @RequestMapping(value = ServerConfig.TOKEN_ENDPOINT, method = RequestMethod.POST)
    public ResponseEntity<?> token(Principal principal, @RequestParam Map<String, String> parameters) {
        return null;
    }
}
