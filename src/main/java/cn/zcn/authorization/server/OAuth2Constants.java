package cn.zcn.authorization.server;

public interface OAuth2Constants {

    String CLIENT_ID = "client_id";
    String CLIENT_SECRET = "client_secret";
    String GRANT_TYPE = "grant_type";
    String CODE = "code";
    String RESPONSE_TYPE = "response_type";
    String REDIRECT_URI = "redirect_uri";
    String STATE = "state";
    String DISPLAY = "display";
    String REQUEST = "request";
    String LOGIN_HINT = "login_hint";
    String MAX_AGE = "max_age";
    String CLAIMS = "claims";
    String SCOPE = "scope";
    String NONCE = "nonce";
    String PROMPT = "prompt";
    String ACR = "acr";
    String REFRESH_TOKEN = "refresh_token";
    String CLIENT_ASSERTION_TYPE = "client_assertion_type";
    String CLIENT_ASSERTION = "client_assertion";
    String RESPONSE_MODE = "response_mode";
    String TOKEN = "token";


    // audience
    String AUD = "aud";

    // prompt values
    String PROMPT_LOGIN = "login";
    String PROMPT_NONE = "none";
    String PROMPT_CONSENT = "consent";
    String PROMPT_SEPARATOR = " ";

    // extensions
    String APPROVED_SITE = "approved_site";

    // PKCE
    String CODE_CHALLENGE = "code_challenge";
    String CODE_CHALLENGE_METHOD = "code_challenge_method";
    String CODE_VERIFIER = "code_verifier";

    String ID_TOKEN = "id_token";

    //MTLS
    String X509CERTIFICATE_THUMBPRINT = "x-x509-x5tS256";

    //oauth response
    String ACCESS_TOKEN = "access_token";
    String TOKEN_TYPE = "token_type";
    String EXPIRES_IN = "expires_in";
    String R_EXPIRES_IN = "r_expires_in";

    String AUTHORIZATION = "Authorization";

    // introspection
    String ISS = "iss";
    String IAT = "iat";
    String SUB = "sub";
    String USERNAME = "username";
    String EXP = "exp";
    String EXPIRES_AT = "expires_at";
    String SCOPE_SEPARATOR = " ";
    String ACTIVE = "active";
    String CNF = "cnf";
    String X5T_S256 = "x5t#S256";

    String ACCESS_TOKEN_TYPE = "access_token_type";
    String BEARER_TYPE = "Bearer";

    // user approval
    String USER_OAUTH_APPROVAL = "user_oauth_approval";
    String SCOPE_PREFIX = "scope.";
}
