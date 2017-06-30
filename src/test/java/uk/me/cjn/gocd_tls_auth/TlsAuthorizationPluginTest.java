package uk.me.cjn.gocd_tls_auth;

import com.google.gson.Gson;
import com.thoughtworks.go.plugin.api.GoApplicationAccessor;
import com.thoughtworks.go.plugin.api.exceptions.UnhandledRequestTypeException;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.security.cert.Extension;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

@RunWith(MockitoJUnitRunner.class)
public class TlsAuthorizationPluginTest {

    private static final String SSL_SUBJECT = "C=GB,L=London,O=British Broadcasting Corporation,OU=Supplier to BBC,CN=Chris Northwood,emailAddress=cnorthwood@gmail.com";
    private Gson gson = new Gson();
    private TlsAuthorizationPlugin tlsAuthorizationPlugin;
    @Mock private GoApplicationAccessor mockGoApplicationAccessor;

    @Before
    public void setUp() {
        tlsAuthorizationPlugin = new TlsAuthorizationPlugin();
        tlsAuthorizationPlugin.initializeGoApplicationAccessor(mockGoApplicationAccessor);
    }

    @Test
    public void unrecognisedResponsesReturn404Code() throws Exception {
        GoPluginApiResponse response = makeRequest("something.that.does.not.exist");
        assertThat(response.responseCode(), is(404));
    }

    @Test
    public void pluginExposesCapabilities() throws Exception {
        GoPluginApiResponse response = makeRequest("go.cd.authorization.get-capabilities");
        assertThat(response.responseCode(), is(200));
        assertThat((String) getResponseField(response, "supported_auth_type"), is("web"));
        assertThat((boolean) getResponseField(response, "can_search"), is(false));
        assertThat((boolean) getResponseField(response, "can_authorize"), is(false));
    }

    @Test
    public void pluginExposesConfigurationMetadata() throws Exception {
        GoPluginApiResponse response = makeRequest("go.cd.authorization.auth-config.get-metadata");

        assertThat(response.responseCode(), is(200));
        assertThat(getResponseList(response).size(), is(0));
    }

    @Test
    public void pluginExposesConfigurationView() throws Exception {
        GoPluginApiResponse response = makeRequest("go.cd.authorization.auth-config.get-view");

        assertThat(response.responseCode(), is(200));
        assertThat((String) getResponseField(response, "template"), is("<div class=\"form_item_block\"><p>No configuration</p></div>"));
    }

    @Test
    public void pluginValidatesAnEmptyConfiguration() throws Exception {
        Map<String, Object> configuration = new HashMap<>();
        GoPluginApiResponse response = makeRequest("go.cd.authorization.auth-config.validate", configuration);

        assertThat(response.responseCode(), is(200));
        assertThat(getResponseList(response).size(), is(0));
    }

    @Test
    public void pluginRejectsAConfigurationWithValues() throws Exception {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("unexpected", "key");
        GoPluginApiResponse response = makeRequest("go.cd.authorization.auth-config.validate", configuration);

        assertThat(response.responseCode(), is(200));
        assertThat(getResponseList(response).size(), is(1));
        assertThat((String) ((Map) getResponseList(response).get(0)).get("key"), is("unexpected"));
        assertThat((String) ((Map) getResponseList(response).get(0)).get("message"), is("invalid configuration key specified"));
    }

    @Test
    public void pluginIsAlwaysConnected() throws Exception {
        GoPluginApiResponse response = makeRequest("go.cd.authorization.auth-config.verify-connection");

        assertThat(response.responseCode(), is(200));
        assertThat((String) getResponseField(response, "status"), is("success"));
        assertThat((String) getResponseField(response, "message"), is("NOOP"));
    }

    @Test
    public void loggingInWithoutCertificatesDoesNotAuthenticateUser() throws Exception {
        GoPluginApiResponse response = makeRequest("go.cd.authorization.fetch-access-token");

        assertThat(response.responseCode(), is(200));
        assertThat(getResponseJson(response).size(), is(0));
    }

    @Test
    public void loggingInWithoutValidCertificatesDoesNotAuthenticateUser() throws Exception {
        GoPluginApiResponse response = makeFetchAccessTokenRequest(SSL_SUBJECT, "NONE");

        assertThat(response.responseCode(), is(200));
        assertThat(getResponseJson(response).size(), is(0));
    }

    @Test
    public void emailFromSubjectIsUsedAsUsernameAndEmailId() throws Exception {
        GoPluginApiResponse response = makeFetchAccessTokenRequest(SSL_SUBJECT, "SUCCESS");

        assertThat(((Map<String, String>) getResponseField(response, "user")).get("username"), is("cnorthwood@gmail.com"));
        assertThat(((Map<String, String>) getResponseField(response, "user")).get("email_id"), is("cnorthwood@gmail.com"));
        assertThat(((List<Object>) getResponseField(response, "roles")).size(), is(0));
    }

    @Test
    public void cnFromSubjectIsUsedAsDisplayName() throws Exception {
        GoPluginApiResponse response = makeFetchAccessTokenRequest(SSL_SUBJECT, "SUCCESS");

        assertThat(((Map<String, String>) getResponseField(response, "user")).get("display_name"), is("Chris Northwood"));
    }

    @Test
    public void malformedSubjectDoesNotAuthenticateUser() throws Exception {
        GoPluginApiResponse response = makeFetchAccessTokenRequest("I am not a valid subject", "SUCCESS");

        assertThat(response.responseCode(), is(200));
        assertThat(getResponseJson(response).size(), is(0));
    }

    @Test
    public void missingCNOrEmailDoesNotAuthenticateUser() throws Exception {
        GoPluginApiResponse response = makeFetchAccessTokenRequest("C=GB", "SUCCESS");

        assertThat(response.responseCode(), is(200));
        assertThat(getResponseJson(response).size(), is(0));
    }

    @Test
    public void credentialsAreFetchedFromHeaders() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put("SSL_CLIENT_S_DN", SSL_SUBJECT);
        headers.put("SSL_CLIENT_VERIFY", "SUCCESS");
        GoPluginApiResponse response = makeRequest("go.cd.authorization.fetch-access-token", headers, null);

        assertThat(response.responseCode(), is(200));
        assertThat((String) getResponseField(response, "SSL_SUBJECT"), is(SSL_SUBJECT));
        assertThat((String) getResponseField(response, "SSL_VERIFY"), is("SUCCESS"));
    }

    @Test
    public void authorizationServerReturnsDirectlyToGoInstance() throws Exception {
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("authorization_server_callback_url", "http://www.example.com");
        GoPluginApiResponse response = makeRequest("go.cd.authorization.authorization-server-url", requestBody);

        assertThat(response.responseCode(), is(200));
        assertThat((String) getResponseField(response, "authorization_server_url"), is("http://www.example.com"));
    }

    private GoPluginApiResponse makeRequest(final String requestName) throws UnhandledRequestTypeException {
        return tlsAuthorizationPlugin.handle(buildRequest(requestName, null, null));
    }

    private GoPluginApiResponse makeRequest(final String requestName, final Map<String, Object> body) throws UnhandledRequestTypeException {
        return tlsAuthorizationPlugin.handle(buildRequest(requestName, null, body));
    }

    private GoPluginApiResponse makeRequest(final String requestName, final Map<String, String> headers, final Map<String, Object> body) throws UnhandledRequestTypeException {
        return tlsAuthorizationPlugin.handle(buildRequest(requestName, headers, body));
    }

    private GoPluginApiResponse makeFetchAccessTokenRequest(final String sslSubject, final String sslVerify) throws UnhandledRequestTypeException {
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("SSL_SUBJECT", sslSubject);
        requestBody.put("SSL_VERIFY", sslVerify);
        return tlsAuthorizationPlugin.handle(buildRequest("go.cd.authorization.authenticate-user", null, requestBody));
    }

    private Map<Object, Object> getResponseJson(GoPluginApiResponse response) {
        return gson.fromJson(response.responseBody(), Map.class);
    }

    private Object getResponseField(GoPluginApiResponse response, String key) {
        return getResponseJson(response).get(key);
    }

    private List getResponseList(GoPluginApiResponse response) {
        return gson.fromJson(response.responseBody(), List.class);
    }

    private GoPluginApiRequest buildRequest(
            final String requestName,
            final Map<String, String> requestHeaders,
            final Map<String, Object> requestBody
    ) {
        return new GoPluginApiRequest() {
            @Override
            public String extension() {
                return null;
            }

            @Override
            public String extensionVersion() {
                return null;
            }

            @Override
            public String requestName() {
                return requestName;
            }

            @Override
            public Map<String, String> requestParameters() {
                return null;
            }

            @Override
            public Map<String, String> requestHeaders() {
                return requestHeaders;
            }

            @Override
            public String requestBody() {
                return gson.toJson(requestBody);
            }
        };
    }

}
