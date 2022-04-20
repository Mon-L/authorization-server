package cn.zcn.authorization.server;

import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.EmbeddedValueResolverAware;
import org.springframework.core.MethodIntrospector;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.util.StringValueResolver;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.Map;

/**
 * 检测Class中带{@link RequestMapping}注解的方法，将对应的{@link RequestMapping}注册到{@link RequestMappingHandlerMapping}中
 */
public class RequestMappingDetector implements EmbeddedValueResolverAware {

    public static final RequestMappingRewriter NOOP_REQUEST_MAPPING_REWRITER = requestMappingInfo -> {
    };

    @Autowired
    private RequestMappingHandlerMapping requestMappingHandlerMapping;

    private StringValueResolver embeddedValueResolver;

    /**
     * 检测给定 Class 中的所有带有{@link RequestMapping}注解的方法，并将其注册到{@link RequestMappingHandlerMapping}
     *
     * @param clazz   待检测的 Class
     * @param handler 待检测的 Class 的实例
     */
    public <T> void detectHandlerMethods(Class<T> clazz, T handler) {
        this.detectHandlerMethods(clazz, handler, NOOP_REQUEST_MAPPING_REWRITER);
    }

    /**
     * 检测给定 Class 中的所有带有{@link RequestMapping}注解的方法，并将其注册到{@link RequestMappingHandlerMapping}
     *
     * @param clazz                  待检测的 Class
     * @param requestMappingRewriter 用于重写{@link RequestMapping}
     * @param handler                待检测的 Class 的实例
     */
    public <T> void detectHandlerMethods(Class<T> clazz, T handler, RequestMappingRewriter requestMappingRewriter) {
        Map<Method, RequestMappingInfo> methods = MethodIntrospector.selectMethods(clazz,
                (MethodIntrospector.MetadataLookup<RequestMappingInfo>) method -> {
                    try {
                        return createRequestMapping(method, requestMappingRewriter);
                    } catch (Throwable ex) {
                        throw new IllegalStateException("Invalid mapping on handler class [" + clazz.getName() + "]: " + method, ex);
                    }
                });

        methods.forEach((method, mapping) -> {
            Method invocableMethod = AopUtils.selectInvocableMethod(method, clazz);
            requestMappingHandlerMapping.registerMapping(mapping, handler, invocableMethod);
        });
    }

    /**
     * 解析方法上的{@link RequestMapping}注解，并生成对应的{@link RequestMappingInfo}
     *
     * @param method                 待解析的方法
     * @param requestMappingRewriter 用于重写{@link RequestMapping}
     * @return RequestMappingInfo，方法上有{@link RequestMapping}注解；null，方法上没有{@link RequestMapping}注解；
     */
    private RequestMappingInfo createRequestMapping(AnnotatedElement method, RequestMappingRewriter requestMappingRewriter) {
        RequestMapping requestMapping = AnnotatedElementUtils.findMergedAnnotation(method, RequestMapping.class);

        if (requestMapping == null) {
            return null;
        }

        RequestMappingInfo.Builder builder = RequestMappingInfo
                .paths(requestMapping.path())
                .methods(requestMapping.method())
                .params(requestMapping.params())
                .headers(requestMapping.headers())
                .consumes(requestMapping.consumes())
                .produces(requestMapping.produces())
                .mappingName(requestMapping.name())
                .options(requestMappingHandlerMapping.getBuilderConfiguration());

        requestMappingRewriter.rewrite(builder);
        builder.paths(resolveEmbeddedValuesInPatterns(requestMapping.path()));

        return builder.build();
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

    public interface RequestMappingRewriter {
        void rewrite(RequestMappingInfo.Builder requestMappingInfo);
    }
}
