package com.ms.infra.example.application.interceptors;

import com.ms.infra.example.application.morganStanleyServices.MsClientAuthTokenService;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;

/**
 * This class is responsible for generating and adding an authorization token to each API call.
 */
public class AuthHeaderInterceptor implements Interceptor {
    /**
     * MsClientAuthTokenService is responsible for generating bearer tokens.
     */
    private final MsClientAuthTokenService msClientAuthTokenService;

    /**
     * Constructor method
     * @param msClientAuthTokenService MS auth token service
     */
    public AuthHeaderInterceptor(MsClientAuthTokenService msClientAuthTokenService) {
        this.msClientAuthTokenService = msClientAuthTokenService;
    }

    /**
     * This function will automatically generate a bearer token and add the authorization header to each API call.
     * @param chain current chain of interceptors
     * @return updated chain with new authorization interceptor
     * @throws IOException throws IOException, if there is an I/O error during getAccessToken()
     */
    @Override
    public Response intercept(Chain chain) throws IOException {
        // add Authorization header to every call with this interceptor
        return chain.proceed(null);
    }
}
