package uk.me.cjn.gocd_tls_auth;

import com.google.gson.Gson;
import com.thoughtworks.go.plugin.api.GoApplicationAccessor;
import com.thoughtworks.go.plugin.api.GoPlugin;
import com.thoughtworks.go.plugin.api.GoPluginIdentifier;
import com.thoughtworks.go.plugin.api.annotation.Extension;
import com.thoughtworks.go.plugin.api.exceptions.UnhandledRequestTypeException;
import com.thoughtworks.go.plugin.api.logging.Logger;
import com.thoughtworks.go.plugin.api.request.GoApiRequest;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Extension
public class TlsAuthenticationPlugin implements GoPlugin {

    private static final String SSL_CLIENT_CERTIFICATE_SUBJECT = "SSL_CLIENT_S_DN";
    private static final String SSL_CLIENT_CERTIFICATE_VERIFY = "SSL_CLIENT_VERIFY";

    private static Logger LOGGER = Logger.getLoggerFor(TlsAuthenticationPlugin.class);

    private final GoPluginIdentifier pluginIdentifier = new GoPluginIdentifier("authentication", Collections.singletonList("1.0"));
    private final Gson gson = new Gson();
    private GoApplicationAccessor goApplicationAccessor;

    @Override
    public void initializeGoApplicationAccessor(GoApplicationAccessor goApplicationAccessor) {
        this.goApplicationAccessor = goApplicationAccessor;
    }

    @Override
    public GoPluginIdentifier pluginIdentifier() {
        return pluginIdentifier;
    }

    @Override
    public GoPluginApiResponse handle(GoPluginApiRequest goPluginApiRequest) throws UnhandledRequestTypeException {
        switch (goPluginApiRequest.requestName()) {
            case "go.authentication.plugin-configuration":
                return buildPluginConfigurationResponse();
            case "index":
                return handleAuthenticateRequest(goPluginApiRequest);
            default:
                return buildResponse(404, null);
        }
    }

    private GoPluginApiResponse handleAuthenticateRequest(GoPluginApiRequest request) {
        try {
            String clientVerify = getHeader(request, SSL_CLIENT_CERTIFICATE_VERIFY);
            if (clientVerify.equalsIgnoreCase("success")) {
                authenticateUser(getHeader(request, SSL_CLIENT_CERTIFICATE_SUBJECT));
            }
        } catch (IllegalArgumentException e) {
            LOGGER.error("No SSL certificate header " + SSL_CLIENT_CERTIFICATE_SUBJECT + " or " + SSL_CLIENT_CERTIFICATE_VERIFY + " in request.");
        }
        return redirectToHomePage();
    }

    private String getHeader(GoPluginApiRequest request, String header) throws IllegalArgumentException {
        if (request.requestHeaders() == null || !request.requestHeaders().containsKey(header)) {
            throw new IllegalArgumentException();
        }
        return request.requestHeaders().get(header);
    }

    private void authenticateUser(String certificateSubject) {
        try {
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
            }
            goApplicationAccessor.submit(makeAuthenticateRequest(email, commonName, email));
        } catch (InvalidNameException e) {
            LOGGER.error("Failed to parse SSL certificate subject: " + certificateSubject);
        }
    }

    private GoApiRequest makeAuthenticateRequest(String username, String displayName, String emailId) {
        Map<String, String> userMap = new HashMap<>();
        userMap.put("email-id", emailId);
        userMap.put("display-name", displayName);
        userMap.put("username", username);
        final Map<String, Map> bodyMap = new HashMap<>();
        bodyMap.put("user", userMap);

        return new GoApiRequest() {
            @Override
            public String api() {
                return "go.processor.authentication.authenticate-user";
            }

            @Override
            public String apiVersion() {
                return "1.0";
            }

            @Override
            public GoPluginIdentifier pluginIdentifier() {
                return pluginIdentifier;
            }

            @Override
            public Map<String, String> requestParameters() {
                return null;
            }

            @Override
            public Map<String, String> requestHeaders() {
                return null;
            }

            @Override
            public String requestBody() {
                return gson.toJson(bodyMap);
            }
        };
    }

    private GoPluginApiResponse redirectToHomePage() {
        Map<String, String> headersMap = new HashMap<>();
        headersMap.put("Location", "/");
        return buildResponse(302, headersMap, null);
    }

    private GoPluginApiResponse buildPluginConfigurationResponse() {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("display-name", "TLS Client Certificates");
        try {
            configuration.put(
                    "display-image-url",
                    "data:image/png;base64," + new String(
                        Base64.encodeBase64(IOUtils.toByteArray(getClass().getClassLoader().getResourceAsStream("login-button.png")))
                    )
            );
        } catch (IOException ioException) {
            LOGGER.error("Failed to load login button image");
        }
        configuration.put("supports-user-search", false);
        configuration.put("supports-password-based-authentication", false);
        configuration.put("supports-web-based-authentication", true);
        return buildResponse(200, configuration);
    }


    private GoPluginApiResponse buildResponse(final int responseCode, Object responseBody) {
        return buildResponse(responseCode, null, responseBody);
    }

    private GoPluginApiResponse buildResponse(
            final int responseCode, final Map<String, String> responseHeaders, final Object responseBody
    ) {
        return new GoPluginApiResponse() {
            @Override
            public int responseCode() {
                return responseCode;
            }

            @Override
            public Map<String, String> responseHeaders() {
                return responseHeaders;
            }

            @Override
            public String responseBody() {
                return gson.toJson(responseBody);
            }
        };
    }
}
