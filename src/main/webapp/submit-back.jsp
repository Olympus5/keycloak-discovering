<%@ page import="org.keycloak.representations.JsonWebToken" %>
<%@ page import="javax.crypto.spec.SecretKeySpec" %>
<%@ page import="org.keycloak.common.util.Base64" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.net.URLDecoder" %>
<%@ page import="java.nio.charset.StandardCharsets" %>
<%@ page import="org.keycloak.jose.jws.JWSBuilder" %>
<%@ page import="java.net.URLEncoder" %>

<%
    String secret = "aSqzP4reFgWR4j94BDT1r+81QYp/NYbY9SBwXtqV1ko=";

    JsonWebToken tokenSentBack = new JsonWebToken();
    SecretKeySpec hmacSecretKeySpec = new SecretKeySpec(Base64.decode(secret), "HmacSHA256");

    for (Map.Entry<String, String[]> me : request.getParameterMap().entrySet()) {
        String name = me.getKey();

        if (!name.startsWith("_")) {
            String decodeValue = URLDecoder.decode(me.getValue()[0], StandardCharsets.UTF_8);
            tokenSentBack.setOtherClaims(name, decodeValue);
        }
    }

    // TODO github MR on keycloak official repo
    String appToken = new JWSBuilder().jsonContent(tokenSentBack).hmac256(hmacSecretKeySpec);
    String encodedToken = URLEncoder.encode(appToken, StandardCharsets.UTF_8);
    String decodedUrl = URLDecoder.decode(request.getParameter("_tokenUrl"), StandardCharsets.UTF_8);

    response.sendRedirect(decodedUrl.replace("{APP_TOKEN}", encodedToken));
%>