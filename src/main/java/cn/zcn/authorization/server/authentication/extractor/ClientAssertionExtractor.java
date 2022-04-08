package cn.zcn.authorization.server.authentication.extractor;

import cn.zcn.authorization.server.OAuth2Constants;
import cn.zcn.authorization.server.authentication.JWTAssertionAuthenticationToken;
import com.google.common.base.Strings;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;

/**
 * 用于抽取Client Assertion
 * 参考规范: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-bearer#section-2.2
 */
public class ClientAssertionExtractor implements AuthenticationExtractor {

    private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static final Logger logger = LoggerFactory.getLogger(ClientAssertionExtractor.class);

    @Override
    public Authentication extract(HttpServletRequest request) throws AuthenticationException {
        String assertion = request.getParameter(OAuth2Constants.CLIENT_ASSERTION);

        JWT jwt;

        try {
            jwt = JWTParser.parse(assertion);

            logger.debug("Client assertion be found in request body: " + jwt.getJWTClaimsSet().getSubject());
        } catch (ParseException e) {
            throw new BadCredentialsException("Invalid JWT credential assertion: " + assertion);
        }

        return new JWTAssertionAuthenticationToken(jwt);
    }

    @Override
    public RequestMatcher getRequestMatcher() {
        return new ClientAssertionRequestMatcher();
    }

    private static class ClientAssertionRequestMatcher implements RequestMatcher {

        @Override
        public boolean matches(HttpServletRequest request) {
            String assertionType = request.getParameter(OAuth2Constants.CLIENT_ASSERTION_TYPE);
            String assertion = request.getParameter(OAuth2Constants.CLIENT_ASSERTION);

            return !Strings.isNullOrEmpty(assertionType) && !Strings.isNullOrEmpty(assertion) && assertionType.equals(ASSERTION_TYPE);
        }
    }
}
