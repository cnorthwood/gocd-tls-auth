package uk.me.cjn.gocd_tls_auth;

import com.google.gson.Gson;
import com.thoughtworks.go.plugin.api.GoApplicationAccessor;
import com.thoughtworks.go.plugin.api.exceptions.UnhandledRequestTypeException;
import com.thoughtworks.go.plugin.api.request.GoApiRequest;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class TlsAuthenticationPluginTest {

    private static final String SSL_SUBJECT = "C=GB,L=London,O=British Broadcasting Corporation,OU=Supplier to BBC,CN=Chris Northwood,emailAddress=cnorthwood@gmail.com";
    private Gson gson = new Gson();
    private TlsAuthenticationPlugin tlsAuthenticationPlugin;
    @Mock private GoApplicationAccessor mockGoApplicationAccessor;

    @Before
    public void setUp() {
        tlsAuthenticationPlugin = new TlsAuthenticationPlugin();
        tlsAuthenticationPlugin.initializeGoApplicationAccessor(mockGoApplicationAccessor);
    }

    @Test
    public void unrecognisedResponsesReturn404Code() throws Exception {
        GoPluginApiResponse response = tlsAuthenticationPlugin.handle(buildRequest("something.that.does.not.exist"));
        assertThat(response.responseCode(), is(404));
    }

    @Test
    public void authenticationPluginSupportsConfigurationRequests() throws Exception {
        GoPluginApiResponse response = makePluginConfigurationRequest();
        assertThat(response.responseCode(), is(200));
    }

    @Test
    public void authenticationPluginHasDisplayName() throws Exception {
        GoPluginApiResponse response = makePluginConfigurationRequest();
        assertThat((String) getResponseField(response, "display-name"), is("TLS Client Certificates"));
    }

    @Test
    public void authenticationPluginDoesNotSupportUserSearch() throws Exception {
        GoPluginApiResponse response = makePluginConfigurationRequest();
        assertThat((boolean) getResponseField(response, "supports-user-search"), is(false));
    }

    @Test
    public void authenticationPluginDoesNotSupportPasswordLogins() throws Exception {
        GoPluginApiResponse response = makePluginConfigurationRequest();
        assertThat((boolean) getResponseField(response, "supports-password-based-authentication"), is(false));
    }

    @Test
    public void authenticationPluginDoesSupportWebBasedLogins() throws Exception {
        GoPluginApiResponse response = makePluginConfigurationRequest();
        assertThat((boolean) getResponseField(response, "supports-web-based-authentication"), is(true));
    }

    @Test
    public void accessingLoginPageSendsYouToTheRoot() throws Exception {
        GoPluginApiResponse response = makeLoginRequest();
        assertThat(response.responseCode(), is(302));
        assertThat(response.responseHeaders().get("Location"), is("/"));
    }

    @Test
    public void accessingLoginPageAuthenticatesUserWithCertificateDetails() throws Exception {
        makeLoginRequest(SSL_SUBJECT, "SUCCESS");
        GoApiRequest apiRequest = captureApiRequest();

        assertThat(apiRequest.api(), is("go.processor.authentication.authenticate-user"));
    }

    @Test
    public void loggingInWithoutCertificatesDoesNotAuthenticateUser() throws Exception {
        tlsAuthenticationPlugin.handle(buildRequest("index"));

        assertApiRequestNeverMade();
    }

    @Test
    public void loggingInWithoutValidCertificatesDoesNotAuthenticateUser() throws Exception {
        makeLoginRequest(SSL_SUBJECT, "NONE");

        assertApiRequestNeverMade();
    }

    @Test
    public void emailFromSubjectIsUsedAsUsernameAndEmailId() throws Exception {
        makeLoginRequest(SSL_SUBJECT, "SUCCESS");
        GoApiRequest apiRequest = captureApiRequest();

        assertThat(getUserFromApiRequest(apiRequest).get("username"), is("cnorthwood@gmail.com"));
        assertThat(getUserFromApiRequest(apiRequest).get("email-id"), is("cnorthwood@gmail.com"));
    }

    @Test
    public void cnFromSubjectIsUsedAsDisplayName() throws Exception {
        makeLoginRequest(SSL_SUBJECT, "SUCCESS");
        GoApiRequest apiRequest = captureApiRequest();

        assertThat(getUserFromApiRequest(apiRequest).get("display-name"), is("Chris Northwood"));
    }

    @Test
    public void malformedSubjectDoesNotAuthenticateUser() throws Exception {
        makeLoginRequest("I am not a valid subject", "SUCCESS");
        assertApiRequestNeverMade();
    }

    @Test
    public void missingCNOrEmailDoesNotAuthenticateUser() throws Exception {
        makeLoginRequest("C=GB", "SUCCESS");
        assertApiRequestNeverMade();
    }

    private GoApiRequest captureApiRequest() {
        ArgumentCaptor<GoApiRequest> apiRequest = ArgumentCaptor.forClass(GoApiRequest.class);
        verify(mockGoApplicationAccessor).submit(apiRequest.capture());
        return apiRequest.getValue();
    }

    private void assertApiRequestNeverMade() {
        verify(mockGoApplicationAccessor, never()).submit(any(GoApiRequest.class));
    }

    private Map<String, String> getUserFromApiRequest(GoApiRequest apiRequest) {
        return (Map<String, String>) gson.fromJson(apiRequest.requestBody(), Map.class).get("user");
    }

    private Object getResponseField(GoPluginApiResponse response, String key) {
        return gson.fromJson(response.responseBody(), Map.class).get(key);
    }

    private GoPluginApiResponse makeLoginRequest() throws UnhandledRequestTypeException {
        return tlsAuthenticationPlugin.handle(buildRequest("index"));
    }

    private GoPluginApiResponse makeLoginRequest(String sslSubject, String sslVerify) throws UnhandledRequestTypeException {
        Map<String, String> headersMap = new HashMap<>();
        headersMap.put("SSL_CLIENT_S_DN", sslSubject);
        headersMap.put("SSL_CLIENT_VERIFY", sslVerify);
        return tlsAuthenticationPlugin.handle(buildRequest("index", headersMap));
    }

    private GoPluginApiResponse makePluginConfigurationRequest() throws UnhandledRequestTypeException {
        return tlsAuthenticationPlugin.handle(buildRequest("go.authentication.plugin-configuration", null));
    }

    private GoPluginApiRequest buildRequest(final String requestName) {
        return buildRequest(requestName, null);
    }

    private GoPluginApiRequest buildRequest(final String requestName, final Map<String, String> headersMap) {
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
                return headersMap;
            }

            @Override
            public String requestBody() {
                return null;
            }
        };
    }

}
