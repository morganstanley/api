package com.ms.infra.example.application;

import com.ms.infra.example.application.config.MicroprofileConfigService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class TestMicroprofileConfigServiceShould {
    private MicroprofileConfigService microprofileConfigService;

    private final String TEST_MS_OAUTH2_TOKEN_URI = "ms-test-uri";
    private final String TEST_CLIENT_APP_ID = "test-client-app-id";
    private final String TEST_CLIENT_APP_SCOPE = "test-client-app-scope";
    private final String TEST_PROXY_HOST = "test-proxy-host";
    private final String TEST_PROXY_PORT = "8080";
    private final String TEST_MS_URL = "https://example-api-domain/";

    private final String INCORRECT_FILE_TYPE_NAME = "file.pem";
    private final String EXPECTED_FILE_ERROR_MESSAGE = "Incorrect file type: " + INCORRECT_FILE_TYPE_NAME + ", file type should be ";
    private final String EXPECTED_PRIVATE_KEY_ERROR_MESSAGE = EXPECTED_FILE_ERROR_MESSAGE + ".der";
    private final String EXPECTED_PUBLIC_CERTIFICATE_ERROR_MESSAGE = EXPECTED_FILE_ERROR_MESSAGE + ".cer";

    @BeforeEach
    void setup_config_service() {
        microprofileConfigService = new MicroprofileConfigService();
    }

    @Test
    void get_correct_ms_token_uri() {
        assertThat("Incorrect value for Morgan Stanley OAuth2 Token URI", microprofileConfigService.getMsOAuth2TokenUri(), is(TEST_MS_OAUTH2_TOKEN_URI));
    }

    @Test
    void get_correct_client_id() {
        assertThat("Incorrect value for Client App ID", microprofileConfigService.getClientAppId(), is(TEST_CLIENT_APP_ID));
    }

    @Test
    void get_correct_client_app_scope() {
        assertThat("Incorrect value for Client App Scope", microprofileConfigService.getClientAppScope(), is(TEST_CLIENT_APP_SCOPE));
    }

    @Test
    void get_correct_ms_api_url() {
        assertThat("Incorrect MS API URL", microprofileConfigService.getMsUrlDomain(), is(TEST_MS_URL));
    }

    @Test
    void set_correct_proxy_host_and_port() {
        assertThat("Proxy host is not correct", System.getProperty("https.proxyHost"), equalTo(TEST_PROXY_HOST));
        assertThat("Proxy port is not correct", System.getProperty("https.proxyPort"), equalTo(TEST_PROXY_PORT));
    }

    @Test
    void error_if_private_key_file_does_not_end_with_der() {
        Exception exception = assertThrows(Exception.class, () -> {
            microprofileConfigService.checkFileExtension(INCORRECT_FILE_TYPE_NAME, ".der");
        });
        assertThat("Incorrect error type", exception, instanceOf(IllegalArgumentException.class));
        assertThat("Wrong error message", exception.getMessage(), is(EXPECTED_PRIVATE_KEY_ERROR_MESSAGE));
    }

    @Test
    void error_if_public_key_file_does_not_end_with_cer() {
        Exception exception = assertThrows(Exception.class, () -> {
            microprofileConfigService.checkFileExtension(INCORRECT_FILE_TYPE_NAME, ".cer");
        });
        assertThat("Incorrect error type", exception, instanceOf(IllegalArgumentException.class));
        assertThat("Wrong error message", exception.getMessage(), is(EXPECTED_PUBLIC_CERTIFICATE_ERROR_MESSAGE));
    }
}
