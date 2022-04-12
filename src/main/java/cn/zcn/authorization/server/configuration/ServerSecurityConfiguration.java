package cn.zcn.authorization.server.configuration;

import cn.zcn.authorization.server.configurer.ServerSecurityConfigurer;
import cn.zcn.authorization.server.endpoint.AuthorizationEndpoint;
import cn.zcn.authorization.server.endpoint.TokenEndpoint;
import cn.zcn.authorization.server.exception.OAuth2ExceptionWriter;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.EmbeddedValueResolverAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.MethodIntrospector;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringValueResolver;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

@Configuration
public class ServerSecurityConfiguration extends WebSecurityConfigurerAdapter implements EmbeddedValueResolverAware {

    private final ServerSecurityConfigurer serverSecurityConfigurer = new ServerSecurityConfigurer();

    private StringValueResolver embeddedValueResolver;

    @Autowired
    private RequestMappingHandlerMapping handlerMapping;

    @Autowired
    public void setConfigurers(List<ServerSecurityConfigurationAdapter> configurers) {
        configurers.sort(AnnotationAwareOrderComparator.INSTANCE);

        for (ServerSecurityConfigurationAdapter adapter : configurers) {
            adapter.configure(serverSecurityConfigurer);
        }
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        serverSecurityConfigurer.init(http);
        RequestMatcher requestMatcher = serverSecurityConfigurer.getRequestMatcher();
        OAuth2ExceptionWriter oAuth2ExceptionWriter = http.getSharedObject(OAuth2ExceptionWriter.class);

        http
                .requestMatcher(requestMatcher).authorizeRequests().anyRequest().fullyAuthenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
                .csrf().ignoringRequestMatchers(requestMatcher)
                .and()
                .exceptionHandling()
                .defaultAuthenticationEntryPointFor((request, response, exception) -> {
                    oAuth2ExceptionWriter.write(exception, new ServletWebRequest(request, response));
                    response.flushBuffer();
                }, requestMatcher);

        for (SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> configurer : serverSecurityConfigurer.getConfigurers().values()) {
            http.apply(configurer);
        }

        /**
         * 动态注册 authorize、token 等 OAuth2 端点
         */
        detectHandlerMethods(AuthorizationEndpoint.class, authorizationEndpoint());
        detectHandlerMethods(TokenEndpoint.class, tokenEndpoint());
    }

    /**
     * 授权端点实例。该类不含 {@link org.springframework.stereotype.Controller}。不会解析其 {@link RequestMapping} 注解
     * @return AuthorizationEndpoint
     */
    @Bean
    public AuthorizationEndpoint authorizationEndpoint() {
        return new AuthorizationEndpoint();
    }

    /**
     * 令牌端点实例。该类不含 {@link org.springframework.stereotype.Controller}。不会解析其 {@link RequestMapping} 注解
     * @return TokenEndpoint
     */
    @Bean
    public TokenEndpoint tokenEndpoint() {
        return new TokenEndpoint();
    }

    /**
     * 查找 Class 内的 {@link RequestMapping}。并注册到 {@link RequestMappingHandlerMapping}
     *
     * @param clazz   待查找的类
     * @param handler 待查找类的实例
     */
    private void detectHandlerMethods(Class<?> clazz, Object handler) {
        Class<?> userType = ClassUtils.getUserClass(clazz);
        Map<Method, RequestMappingInfo> methods = MethodIntrospector.selectMethods(userType,
                (MethodIntrospector.MetadataLookup<RequestMappingInfo>) method -> {
                    try {
                        return createRequestMapping(method);
                    } catch (Throwable ex) {
                        throw new IllegalStateException("Invalid mapping on handler class [" + userType.getName() + "]: " + method, ex);
                    }
                });

        methods.forEach((method, mapping) -> {
            Method invocableMethod = AopUtils.selectInvocableMethod(method, userType);
            handlerMapping.registerMapping(mapping, handler, invocableMethod);
        });
    }

    /**
     * 解析方法上的 {@link RequestMapping} 注解，生成 {@link RequestMappingInfo}
     *
     * @param method 待解析的方法
     * @return RequestMappingInfo
     */
    private RequestMappingInfo createRequestMapping(AnnotatedElement method) {
        RequestMapping requestMapping = AnnotatedElementUtils.findMergedAnnotation(method, RequestMapping.class);

        if (requestMapping == null) {
            return null;
        }

        return RequestMappingInfo
                .paths(resolveEmbeddedValuesInPatterns(requestMapping.path()))
                .methods(requestMapping.method())
                .params(requestMapping.params())
                .headers(requestMapping.headers())
                .consumes(requestMapping.consumes())
                .produces(requestMapping.produces())
                .mappingName(requestMapping.name())
                .options(handlerMapping.getBuilderConfiguration())
                .build();
    }

    private String[] resolveEmbeddedValuesInPatterns(String[] patterns) {
        if (this.embeddedValueResolver == null) {
            return patterns;
        } else {
            String[] resolvedPatterns = new String[patterns.length];
            for (int i = 0; i < patterns.length; i++) {
                resolvedPatterns[i] = this.embeddedValueResolver.resolveStringValue(patterns[i]);
            }
            return resolvedPatterns;
        }
    }

    @Override
    public void setEmbeddedValueResolver(StringValueResolver resolver) {
        this.embeddedValueResolver = resolver;
    }
}
