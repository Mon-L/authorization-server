package cn.zcn.authorization.server;

public interface OAuth2Constants {

    final class GRANT_TYPE{
        public static final String AUTHORIZATION_CODE = "authorization_code";
        public static final String IMPLICIT = "implicit";
        public static final String CLIENT_CREDENTIALS = "client_credentials";
        public static final String PASSWORD = "password";
    }

    final class ERROR{
        public static final String ERROR = "error";
        public static final String ERROR_DESCRIPTION = "error_description";
        public static final String ERROR_URI = "error_uri";
    }

    final class PKCE{
        public static final String CODE_CHALLENGE = "code_challenge";
        public static final  String CODE_CHALLENGE_METHOD = "code_challenge_method";
        public static final String CODE_VERIFIER = "code_verifier";
    }

    final class FIELD{
        public static final String CLIENT_ID = "client_id";
        public static final String CLIENT_SECRET = "client_secret";
        public static final String GRANT_TYPE = "grant_type";
        public static final String CODE = "code";
        public static final String RESPONSE_TYPE = "response_type";
        public static final String REDIRECT_URI = "redirect_uri";
        public static final String STATE = "state";
        public static final String DISPLAY = "display";
        public static final String REQUEST = "request";
        public static final String LOGIN_HINT = "login_hint";
        public static final String MAX_AGE = "max_age";
        public static final String CLAIMS = "claims";
        public static final String SCOPE = "scope";
        public static final String NONCE = "nonce";
        public static final String PROMPT = "prompt";
        public static final String ACR = "acr";
        public static final String REFRESH_TOKEN = "refresh_token";
        public static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";
        public static final String CLIENT_ASSERTION = "client_assertion";
        public static final String RESPONSE_MODE = "response_mode";
        public static final String TOKEN = "token";

        // audience
        public static final String AUD = "aud";

        // prompt values
        public static final String PROMPT_LOGIN = "login";
        public static final String PROMPT_NONE = "none";
        public static final String PROMPT_CONSENT = "consent";
        public static final String PROMPT_SEPARATOR = " ";

        // extensions
        public static final  String APPROVED_SITE = "approved_site";

        public static final String ID_TOKEN = "id_token";

        //MTLS
        public static final String X509CERTIFICATE_THUMBPRINT = "x-x509-x5tS256";

        //oauth response
        public static final String ACCESS_TOKEN = "access_token";
        public static final String TOKEN_TYPE = "token_type";
        public static final String EXPIRES_IN = "expires_in";
        public static final String R_EXPIRES_IN = "r_expires_in";

        public static final String AUTHORIZATION = "Authorization";

        // introspection
        public static final String ISS = "iss";
        public static final String IAT = "iat";
        public static final String SUB = "sub";
        public static final String USERNAME = "username";
        public static final String EXP = "exp";
        public static final String EXPIRES_AT = "expires_at";
        public static final String SCOPE_SEPARATOR = " ";
        public static final String ACTIVE = "active";
        public static final String CNF = "cnf";
        public static final String X5T_S256 = "x5t#S256";

        public static final String ACCESS_TOKEN_TYPE = "access_token_type";
        public static final String BEARER_TYPE = "Bearer";

        // user approval
        public static final String USER_OAUTH_APPROVAL = "user_oauth_approval";
        public static final String SCOPE_PREFIX = "scope.";
    }
}
