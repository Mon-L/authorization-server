package cn.zcn.authorization.server;


public interface ClientService {

    /**
     * 根据客户端ID获取客户端信息
     *
     * @param clientId 客户端ID
     * @return 客户端信息
     */
    Client loadClientByClientId(String clientId);
}
