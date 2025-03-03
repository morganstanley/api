package com.ms.infra.example.application;

import com.ms.infra.example.application.config.MicroprofileConfigService;
import com.ms.infra.example.application.websocket.WebSocketService;
import io.fabric8.mockwebserver.DefaultMockServer;
import io.fabric8.mockwebserver.http.RecordedRequest;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.logging.HttpLoggingInterceptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

public class E2eTest {
    DefaultMockServer mockServer;
    private final String API_URL = "/wss://api-uat.morganstanley.com/";
    private final String MOCK_BEARER_TOKEN = "token";
    private final int TIMEOUT = 1000;

    @BeforeEach
    void setup() {
        mockServer = new DefaultMockServer();
        mockServer.start();
    }

    @AfterEach
    void tearDown() {
        mockServer.shutdown();
    }

    @Test
    void e2eTest() throws Exception {
        // Create microprofileConfigService spy
        MicroprofileConfigService microprofileConfigServiceSpy = spy(new MicroprofileConfigService());
        doReturn(mock(PrivateKey.class)).when(microprofileConfigServiceSpy).getPrivateKey();
        doReturn(mock(X509Certificate.class)).when(microprofileConfigServiceSpy).getPublicCertificate();

        // Create webSocketServiceSpy
        WebSocketService webSocketServiceSpy = spy(new WebSocketService(microprofileConfigServiceSpy, mockServer.url(API_URL).toString(), HttpLoggingInterceptor.Level.BODY));
        doReturn(MOCK_BEARER_TOKEN).when(webSocketServiceSpy).getAuthToken();

        // prevent websocket from reconnecting
        doCallRealMethod()
                .doReturn(mock(WebSocket.class))
                .when(webSocketServiceSpy)
                .connect();

        mockServer.expect().withPath(API_URL)
            .andUpgradeToWebSocket()
            .open()
            .expect("create root").andEmit("CREATED").once()
            .done()
            .once();

        WebSocket websocket = webSocketServiceSpy.connect();
        websocket.send("create root");

        // check connections opens and message gets received
        verify(webSocketServiceSpy, timeout(TIMEOUT).atLeast(1)).onOpen(any(WebSocket.class), any(Response.class));
        verify(webSocketServiceSpy, timeout(TIMEOUT).atLeast(1)).onMessage(any(WebSocket.class), anyString());

        // Check the request hit the right endpoint and had the correct auth header
        RecordedRequest recordedRequest = mockServer.takeRequest();
        assertThat("Incorrect path called",  recordedRequest.getPath(), is(API_URL));
        assertThat("Incorrect auth header", recordedRequest.getHeader("Authorization"), is("Bearer " + MOCK_BEARER_TOKEN));
    }
}
