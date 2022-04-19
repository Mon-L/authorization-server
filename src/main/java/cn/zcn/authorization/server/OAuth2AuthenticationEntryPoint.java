package cn.zcn.authorization.server;

import cn.zcn.authorization.server.exception.DefaultExceptionWriter;
import cn.zcn.authorization.server.exception.ExceptionWriter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 授权失败时的处理器。将错误信息写回给客户端
 */
public class OAuth2AuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ExceptionWriter exceptionWriter = new DefaultExceptionWriter();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        exceptionWriter.write(authException, new ServletWebRequest(request, response));
        response.flushBuffer();
    }
}
