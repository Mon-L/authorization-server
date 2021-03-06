package cn.zcn.authorization.server.utils;

import cn.zcn.authorization.server.OAuth2Constants;
import com.nimbusds.jose.util.Base64URL;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class OAuth2Utils {
    public static String joinParameterString(Set<String> scope) {
        StringJoiner joiner = new StringJoiner(" ");
        for (String s : scope) {
            joiner.add(s);
        }
        return joiner.toString();
    }

    public static Set<String> parseParameterList(String values) {
        Set<String> result = new TreeSet<>();
        if (values != null && values.trim().length() > 0) {
            String[] tokens = values.split("[\\s+]");
            result.addAll(Arrays.asList(tokens));
        }
        return result;
    }

    public static String createCodeChallenge(String codeChallengeMethod, String codeVerifier) throws NoSuchAlgorithmException {
        if (codeChallengeMethod.equals(OAuth2Constants.PKCE.PLAIN)) {
            return codeVerifier;
        } else if (codeChallengeMethod.equals(OAuth2Constants.PKCE.S256)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64URL.encode(bytes).toString();
        }

        throw new IllegalArgumentException("Illegal code challenge method : " + codeChallengeMethod);
    }

    /**
     * 拼装重定向 URL，需要区分重定向参数是否添加在 fragment 上。同时需要处理 redirect uri 已编码和未编码两种情况
     *
     * @param uri        重定向 URL
     * @param parameters 重定向参数
     * @param isFragment 重定向参数是否 添加在 fragment 上
     * @return 编码后的重定向 URL
     */
    public static String appendRedirectUri(String uri, Map<String, ?> parameters, boolean isFragment) {
        UriComponentsBuilder template = UriComponentsBuilder.newInstance();
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri);

        URI redirectUri;
        try {
            // 判断 uri 是否编码
            redirectUri = builder.build(true).toUri();
        } catch (Exception e) {
            // uri 未编码
            redirectUri = builder.build().toUri();
            builder = UriComponentsBuilder.fromUri(redirectUri);
        }

        //复制 uri 到 template builder
        template.scheme(redirectUri.getScheme()).host(redirectUri.getHost())
                .port(redirectUri.getPort()).userInfo(redirectUri.getUserInfo()).path(redirectUri.getPath());

        if (isFragment) {
            StringBuilder fragment = new StringBuilder();
            if (redirectUri.getFragment() != null) {
                fragment.append(redirectUri.getFragment());
            }

            if (parameters.size() > 0) {
                for (Map.Entry<String, ?> entry : parameters.entrySet()) {
                    if (fragment.length() > 0) {
                        fragment.append("&");
                    }

                    fragment.append(entry.getKey()).append("={").append(entry.getKey()).append("}");
                }
                template.fragment(fragment.toString());
            }

            UriComponents encodedUri = template.build().expand(parameters).encode();
            builder.fragment(encodedUri.getFragment());
        } else {
            template.fragment(redirectUri.getFragment());
            for (Map.Entry<String, ?> entry : parameters.entrySet()) {
                template.queryParam(entry.getKey(), "{" + entry.getKey() + "}");
            }
            UriComponents encodedUri = template.build().expand(parameters).encode();
            builder.query(encodedUri.getQuery());
        }

        return builder.build().toUriString();
    }

    /**
     * 当无法解析 URL 的 protocol 时，判断两个 URL 是否相等。否则判断两个 URL 是否满足以下所有条件
     * 1. protocol 相等。
     * 2. host 相等。
     * 3. port 相等。
     * 4. registerURL 的 path 与 requestURL 的 path 相等。
     *
     * @param requestURL
     * @param registerURL
     * @return ture，匹配；false，不匹配；
     */
    public static boolean urlMatches(String requestURL, String registerURL) {
        try {
            //首先解码URL
            URL req = new URL(URLDecoder.decode(requestURL, StandardCharsets.UTF_8.name()));
            URL reg = new URL(URLDecoder.decode(registerURL, StandardCharsets.UTF_8.name()));

            return req.getProtocol().equals(reg.getProtocol()) &&
                    req.getHost().equals(reg.getHost()) &&
                    req.getPort() == reg.getPort() &&
                    StringUtils.cleanPath(req.getPath()).equals(StringUtils.cleanPath(reg.getPath()));

        } catch (MalformedURLException | UnsupportedEncodingException ignored) {
        }

        return requestURL.equals(registerURL);
    }
}
