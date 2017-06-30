package uk.me.cjn.gocd_tls_auth;

import com.google.gson.Gson;
import com.thoughtworks.go.plugin.api.GoApplicationAccessor;
import com.thoughtworks.go.plugin.api.GoPlugin;
import com.thoughtworks.go.plugin.api.GoPluginIdentifier;
import com.thoughtworks.go.plugin.api.annotation.Extension;
import com.thoughtworks.go.plugin.api.exceptions.UnhandledRequestTypeException;
import com.thoughtworks.go.plugin.api.logging.Logger;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import org.apache.commons.io.IOUtils;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.IOException;
import java.util.*;

@Extension
public class TlsAuthorizationPlugin implements GoPlugin {

    private static Logger LOGGER = Logger.getLoggerFor(TlsAuthorizationPlugin.class);
    private static final String SSL_CLIENT_CERTIFICATE_SUBJECT = "SSL_CLIENT_S_DN";
    private static final String SSL_CLIENT_CERTIFICATE_VERIFY = "SSL_CLIENT_VERIFY";
    private final GoPluginIdentifier pluginIdentifier = new GoPluginIdentifier("authorization", Collections.singletonList("1.0"));
    private final Gson gson = new Gson();

    @Override
    public void initializeGoApplicationAccessor(GoApplicationAccessor goApplicationAccessor) {
    }

    @Override
    public GoPluginIdentifier pluginIdentifier() {
        return pluginIdentifier;
    }

    @Override
    public GoPluginApiResponse handle(GoPluginApiRequest request) throws UnhandledRequestTypeException {
        switch (request.requestName()) {
            case "go.cd.authorization.get-icon":
                return buildIconResponse();
            case "go.cd.authorization.get-capabilities":
                return buildCapabilitiesResponse();
            case "go.cd.authorization.auth-config.get-metadata":
                return buildMetadataResponse();
            case "go.cd.authorization.auth-config.get-view":
                return buildConfigurationViewResponse();
            case "go.cd.authorization.auth-config.validate":
                return buildValidateConfigResponse(request.requestBody());
            case "go.cd.authorization.auth-config.verify-connection":
                return buildVerifyConnectionResponse();
            case "go.cd.authorization.fetch-access-token":
                return handleFetchAccessTokenRequest(request);
            case "go.cd.authorization.authenticate-user":
                return handleAuthenticateRequest(request);
            case "go.cd.authorization.authorization-server-url":
                return buildAuthorizationServerUrlResponse(request);
            default:
                return buildResponse(404, null);
        }
    }

    private GoPluginApiResponse buildIconResponse() {
        Map<String, Object> iconResponseBody = new HashMap<>();
        iconResponseBody.put("content_type", "image/svg+xml");
        try {
            iconResponseBody.put("data", new String(
                    org.apache.commons.codec.binary.Base64.encodeBase64(
                            IOUtils.toByteArray(
                                    getClass().getClassLoader().getResourceAsStream("icon.svg")
                            )
                    )
            ));
        } catch (IOException ioException) {
            LOGGER.error("Failed to load login button image");
            return buildResponse(500, "");
        }
        return buildResponse(200, iconResponseBody);
    }

    private GoPluginApiResponse buildCapabilitiesResponse() {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("supported_auth_type", "web");
        configuration.put("can_search", false);
        configuration.put("can_authorize", false);
        return buildResponse(200, configuration);
    }

    private GoPluginApiResponse buildMetadataResponse() {
        List<Map<String, Map<String, String>>> metadata = new ArrayList<>();
        return buildResponse(200, metadata);
    }

    private GoPluginApiResponse buildConfigurationViewResponse() {
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("template", "<div class=\"form_item_block\"><p>No configuration</p></div>");
        return buildResponse(200, responseBody);
    }

    private GoPluginApiResponse buildValidateConfigResponse(String requestBody) {
        Map<String, String> configuration = gson.fromJson(requestBody, Map.class);
        List<Map<String, String>> validationErrors = new LinkedList<>();

        for (String key : configuration.keySet()) {
            Map<String, String> error = new HashMap<>();
            error.put("key", key);
            error.put("message", "invalid configuration key specified");
            validationErrors.add(error);
        }

        return buildResponse(200, validationErrors);
    }

    private GoPluginApiResponse buildVerifyConnectionResponse() {
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("status", "success");
        responseBody.put("message", "NOOP");
        return buildResponse(200, responseBody);
    }

    private GoPluginApiResponse handleFetchAccessTokenRequest(GoPluginApiRequest request) {
        Map<String, String> credentials = new HashMap<>();
        try {
            String sslVerify = getHeader(request, SSL_CLIENT_CERTIFICATE_VERIFY);
            String sslSubject = getHeader(request, SSL_CLIENT_CERTIFICATE_SUBJECT);
            credentials.put("SSL_VERIFY", sslVerify);
            credentials.put("SSL_SUBJECT", sslSubject);
        } catch (IllegalArgumentException e) {
            LOGGER.error("No SSL certificate header " + SSL_CLIENT_CERTIFICATE_SUBJECT + " or " + SSL_CLIENT_CERTIFICATE_VERIFY + " in request.");
        }
        return buildResponse(200, credentials);
    }

    private GoPluginApiResponse buildAuthorizationServerUrlResponse(GoPluginApiRequest request) {
        Map<String, Object> requestBody = gson.fromJson(request.requestBody(), Map.class);
        String authorizationServerCallbackUrl = (String) requestBody.get("authorization_server_callback_url");
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("authorization_server_url", authorizationServerCallbackUrl);
        return buildResponse(200, responseBody);
    }

    private GoPluginApiResponse handleAuthenticateRequest(GoPluginApiRequest request) {
        Map<String, String> suppliedCredentials = gson.fromJson(request.requestBody(), Map.class);
        String sslVerify = suppliedCredentials.get("SSL_VERIFY");
        String sslSubject = suppliedCredentials.get("SSL_SUBJECT");

        if (sslVerify == null || sslSubject == null || !sslVerify.equalsIgnoreCase("success")) {
            return buildResponse(200, new HashMap<>());
        }

        return buildResponse(200, fetchUserCredentialsFromCertificate(sslSubject));
    }

    private String getHeader(GoPluginApiRequest request, String header) throws IllegalArgumentException {
        if (request.requestHeaders() == null || !request.requestHeaders().containsKey(header)) {
            throw new IllegalArgumentException();
        }
        return request.requestHeaders().get(header);
    }

    private Map<String, Object> fetchUserCredentialsFromCertificate(String certificateSubject) {
        Map<String, Object> authenticationResult = new HashMap<>();

        try {
            Map<String, String> user = new HashMap<>();
            LdapName parsedSubject = new LdapName(certificateSubject);
            String email = null;
            String commonName = null;

            for (Rdn rdn : parsedSubject.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("emailAddress")) {
                    email = (String) rdn.getValue();
                }
                if (rdn.getType().equalsIgnoreCase("CN")) {
                    commonName = (String) rdn.getValue();
                }
            }

            if (email == null || commonName == null) {
                throw new InvalidNameException();
            } else {
                user.put("username", email);
                user.put("email_id", email);
                user.put("display_name", commonName);
                authenticationResult.put("user", user);
                authenticationResult.put("roles", new ArrayList<>());
            }
        } catch (InvalidNameException e) {
            LOGGER.error("Failed to parse SSL certificate subject: " + certificateSubject);
        }
        return authenticationResult;
    }

    private GoPluginApiResponse buildResponse(
            final int responseCode, final Object responseBody
    ) {
        return new GoPluginApiResponse() {
            @Override
            public int responseCode() {
                return responseCode;
            }

            @Override
            public Map<String, String> responseHeaders() {
                return null;
            }

            @Override
            public String responseBody() {
                return gson.toJson(responseBody);
            }
        };
    }
}
