package com.ms.infra.example.application;

import com.ms.infra.example.application.morganStanleyServices.MsClientAuthTokenService;
import com.ms.infra.example.application.websocket.WebSocketService;
import io.fabric8.mockwebserver.http.RecordedRequest;
import okhttp3.Response;
import okhttp3.WebSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import io.fabric8.mockwebserver.DefaultMockServer;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TestWebSocketServiceShould {
    private MsClientAuthTokenService msClientAuthTokenService;
    private DefaultMockServer server;

    private final String TEST_AUTH_TOKEN = "MOCK_BEARER_TOKEN";
    private final String API_URL = "/wss/";

    private final int TIMEOUT = 1000;

    @BeforeEach
    void setup() throws Exception {
        // Mock MsClientAuthTokenService
        msClientAuthTokenService = mock(MsClientAuthTokenService.class);
        when(msClientAuthTokenService.getAccessToken()).thenReturn(TEST_AUTH_TOKEN);

        // start mock web server
        server = new DefaultMockServer();
        server.start();
    }

    @AfterEach
    void shutdown_mock_server() {
        server.shutdown();
    }

    @Test
    void call_correct_endpoint_with_auth_token_header() throws Exception {
        server.expect().withPath(API_URL)
            .andUpgradeToWebSocket()
            .open()
            .done()
            .once();

        WebSocketService webSocketService = new WebSocketService(server.url(API_URL), msClientAuthTokenService);
        WebSocketService webSocketServiceSpy = spy(webSocketService);

        // once the mock server connects, it closes the connection
        // this prevents it from trying to reconnect
        doNothing().when(webSocketServiceSpy)
                .onFailure(any(), any(), any());
        WebSocket webSocket = webSocketServiceSpy.connect();
        webSocket.close(1000, null);

        // Check the request
        RecordedRequest recordedRequest = server.takeRequest();
        assertThat("Incorrect path called",  recordedRequest.getPath(), is(API_URL));
        assertThat("Incorrect auth header", recordedRequest.getHeader("Authorization"), is("Bearer " + TEST_AUTH_TOKEN));
    }

    @Test
    void connect_and_receive_message() throws Exception {
        // Define the expected behavior of the server
        server.expect().withPath(API_URL)
            .andUpgradeToWebSocket()
            .open()
            .expect("create root").andEmit("CREATED").once()
            .done()
            .once();

        // Create a WebSocketService instance
        WebSocketService webSocketService = new WebSocketService(server.url(API_URL), msClientAuthTokenService);
        WebSocketService webSocketServiceSpy = spy(webSocketService);

        //prevent websocket from reconnecting
        doNothing().when(webSocketServiceSpy)
                .onFailure(any(), any(), any());

        // Connect to the WebSocket
        WebSocket websocket = webSocketServiceSpy.connect();
        websocket.send("create root");

        // verify connection
        verify(webSocketServiceSpy, timeout(TIMEOUT).atLeast(1)).onOpen(any(WebSocket.class), any(Response.class));
        // verify onMessage function gets called
        verify(webSocketServiceSpy, timeout(TIMEOUT).atLeast(1)).onMessage(any(WebSocket.class), anyString());
    }

    @Test
    void retry_connection_if_fails() throws Exception {
        // Once connection is made with the mock server, then it will close it
        server.expect().withPath(API_URL)
            .andUpgradeToWebSocket()
            .open()
            .done()
            .once();

        WebSocketService webSocketService = new WebSocketService(server.url(API_URL), msClientAuthTokenService);
        WebSocketService webSocketServiceSpy = spy(webSocketService);
        // mock so that it does not try to reconnect a second time
        doCallRealMethod()
                .doReturn(mock(WebSocket.class))
                .when(webSocketServiceSpy)
                .connect();

        WebSocket websocket = webSocketServiceSpy.connect();

        // verify the onFailure method gets called
        verify(webSocketServiceSpy, timeout(TIMEOUT).atLeast(1)).onClosed(any(WebSocket.class), anyInt(), anyString());

        // verify attempted to connect at least twice
        verify(webSocketServiceSpy, timeout(TIMEOUT).atLeast(2)).connect();
        websocket.close(1000, null);
    }

    @Test
    void return_null_token_if_error() throws Exception {
        MsClientAuthTokenService msClientAuthTokenServiceMock = mock(MsClientAuthTokenService.class);
        when(msClientAuthTokenServiceMock.getAccessToken()).thenThrow(new Exception());
        WebSocketService webSocketService = new WebSocketService("url", msClientAuthTokenServiceMock);

        String token = webSocketService.getAuthToken();
        assertThat("Auth token should be null", token, is(""));
    }
}
