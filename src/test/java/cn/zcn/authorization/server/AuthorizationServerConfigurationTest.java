package cn.zcn.authorization.server;

import cn.zcn.authorization.server.configuration.AuthorizationServerConfigurationAdapter;
import cn.zcn.authorization.server.configuration.EnableAuthorizationServer;
import cn.zcn.authorization.server.configurer.AuthorizationEndpointConfigurer;
import cn.zcn.authorization.server.configurer.AuthorizationServerConfigurer;
import cn.zcn.authorization.server.configurer.ClientAuthenticationConfigurer;
import cn.zcn.authorization.server.configurer.TokenEndpointConfigurer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.config.Customizer;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.ServletRequestPathUtils;

import javax.servlet.http.HttpServletRequest;

@SpringBootTest(classes = AuthorizationServerConfigurationTest.Boot.class)
public class AuthorizationServerConfigurationTest {

    @Autowired
    private RequestMappingHandlerMapping handlerMapping;

    @SpringBootApplication
    public static class Boot {
        public static void main(String[] args) {
            new SpringApplication(Boot.class).run(args);
        }

        @Bean
        public ClientService clientService() {
            return clientId -> null;
        }

        @EnableAuthorizationServer
        private class AuthorizationServerConfiguration extends AuthorizationServerConfigurationAdapter {
            @Override
            public void configure(AuthorizationServerConfigurer authorizationServerConfigurer) {

                authorizationServerConfigurer
                        .clientService(clientService())
                        .clientAuthentication(new Customizer<ClientAuthenticationConfigurer>() {
                            @Override
                            public void customize(ClientAuthenticationConfigurer configurer) {

                            }
                        })
                        .authorizationEndpoint(new Customizer<AuthorizationEndpointConfigurer>() {
                            @Override
                            public void customize(AuthorizationEndpointConfigurer configurer) {

                            }
                        })
                        .tokenEndpoint(new Customizer<TokenEndpointConfigurer>() {
                            @Override
                            public void customize(TokenEndpointConfigurer configurer) {

                            }
                        });
            }
        }
    }

    @Test
    public void checkAuthorizationEndpoint() throws Exception {
        HttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), ServerConfig.AUTHORIZATION_ENDPOINT);
        request.setAttribute(ServletRequestPathUtils.PATH_ATTRIBUTE, ServletRequestPathUtils.parseAndCache(request));
        HandlerExecutionChain chain = handlerMapping.getHandler(request);
        Assertions.assertNotNull(chain);
    }

    @Test
    public void checkTokenEndpoint() throws Exception {
        HttpServletRequest request = new MockHttpServletRequest(HttpMethod.POST.name(), ServerConfig.TOKEN_ENDPOINT);
        request.setAttribute(ServletRequestPathUtils.PATH_ATTRIBUTE, ServletRequestPathUtils.parseAndCache(request));
        HandlerExecutionChain chain = handlerMapping.getHandler(request);
        Assertions.assertNotNull(chain);
    }
}
