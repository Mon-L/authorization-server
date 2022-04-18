package cn.zcn.authorization.server.exception;

import org.springframework.web.context.request.ServletWebRequest;

import java.io.IOException;

/**
 * 将异常信息写出到{@link ServletWebRequest#getNativeResponse()}.
 * 该类响应的异常信息必须遵循 OAuth2 规范中定义的 Error Response 的格式
 */
public interface ExceptionWriter {

    void write(Exception e, ServletWebRequest webRequest) throws IOException;

}
