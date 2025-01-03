package com.ms.infra.example.application.morganStanleyServices;

import com.ms.infra.example.application.config.MicroprofileConfigService;
import com.ms.infra.example.application.interceptors.AuthHeaderInterceptor;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.logging.HttpLoggingInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import okhttp3.logging.HttpLoggingInterceptor.Level;

import java.io.IOException;

/**
 * This class is responsible for setting up the retrofit instance.
 * It automatically gets the config using the MicroprofileConfigService class and adds authorization interceptor to each API call.
 */
public class MsRetrofitWrapper {
    /**
     * Logging
     */
    private static final Logger logger = LoggerFactory.getLogger(MsRetrofitWrapper.class);

    /**
     * Configured retrofit instance
     */
    private final Retrofit retrofit;

    /**
     * Responsible for getting auth tokens
     */
    private final MsClientAuthTokenService msClientAuthTokenService;

    /**
     * Gets config values from microprofile config
     */
    private static final MicroprofileConfigService MICROPROFILE_CONFIG_SERVICE = new MicroprofileConfigService();

    /**
     * API Url
     */
    private final String url;

    private final Level logLevel;
    /**
     * Constructor
     * @param url API url
     * @param logLevel Log interceptor level
     * @throws Exception throws exception if error when creating msClientAuthTokenService
     */
    public MsRetrofitWrapper(String url, Level logLevel) throws Exception {
        this.msClientAuthTokenService = new MsClientAuthTokenService(MICROPROFILE_CONFIG_SERVICE);
        this.url = url;
        this.logLevel = logLevel;
        this.retrofit = new Retrofit.Builder()
            .baseUrl(url)
            .addConverterFactory(JacksonConverterFactory.create())
            .client(this.getOkHttpClient(logLevel))
            .build();
    }

    /**
     * Constructor for custom okHttpClient
     * @param url API url
     * @param okHttpClient pre-configured OkHttp Client
     */
    public MsRetrofitWrapper(HttpUrl url, OkHttpClient okHttpClient, Level logLevel) {
        this.msClientAuthTokenService = null;
        this.url = url.toString();
        this.logLevel = logLevel;
        this.retrofit = new Retrofit.Builder()
            .baseUrl(url)
            .addConverterFactory(JacksonConverterFactory.create())
            .client(okHttpClient)
            .build();
    }

    /**
     * This method configures the OkHttp Client.
     * It adds logging and authorization interceptor.
     * @param logLevel log level
     * @return configured okhttp client
     */
    public OkHttpClient getOkHttpClient(Level logLevel) {
        HttpLoggingInterceptor loggingInterceptor = new HttpLoggingInterceptor();
        loggingInterceptor.setLevel(logLevel);

        AuthHeaderInterceptor authHeaderInterceptor = new AuthHeaderInterceptor(msClientAuthTokenService);

        return new OkHttpClient.Builder()
            .addInterceptor(loggingInterceptor)
            .addInterceptor(authHeaderInterceptor)
            .build();
    }

    /**
     * Return the retrofit instance.
     * @return Retrofit instance
     */
    public Retrofit getRetrofit() {
        return this.retrofit;
    }

    /**
     * This method uses the retrofit instance and defined service interface to create a retrofit service.
     * @param serviceInterface service interface to be used
     * @return instance of serviceInterface, created by retrofit
     * @param <T> interface type
     */
    public <T> T createService(Class<T> serviceInterface) {
        return this.getRetrofit().create(serviceInterface);
    }

    public void checkAuthorisation(String apiEndpoint) throws IOException {
        Request request = new Request.Builder()
                .url(this.url + apiEndpoint)
                .build();

        OkHttpClient httpClient = getOkHttpClient(this.logLevel);
        // Execute the request and handle the response
        Response response = httpClient.newCall(request).execute();
        logger.info("Response code: {}", response.code());
        logger.info("Response: {}", response.body().toString());
    }
}
