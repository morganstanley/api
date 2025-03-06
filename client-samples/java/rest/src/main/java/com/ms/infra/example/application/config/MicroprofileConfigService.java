package com.ms.infra.example.application.config;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Optional;

/**
 * This class reads configuration properties using the Microprofile library.
 */
public class MicroprofileConfigService {
    /**
     * Logging
     */
    private static final Logger logger = LoggerFactory.getLogger(MicroprofileConfigService.class);

    /**
     * Config provider
     */
    private final Config configProvider = ConfigProvider.getConfig();

    /**
     * MS OAuth2 Token URI
     */
    private final String morganStanleyOAuth2TokenUri;

    /**
     * Client App ID
     */
    private final String clientAppId;

    /**
     * Client App Scope
     */
    private final String clientAppScope;

    /**
     * Private key file name
     */
    private String privateKeyFile;

    /**
     * Public certification file name
     */
    private String publicCertificateFile;

    /**
     * Morgan Stanley API Url Domain
     */
    private String msUrlDomain;

    /**
     * Constructor method
     * Reads values from config into class
     */
    public MicroprofileConfigService() {
        this.morganStanleyOAuth2TokenUri = configProvider.getValue("morgan-stanley-oauth2-token-uri", String.class);
        this.clientAppId = configProvider.getValue("client-app-id", String.class);
        this.clientAppScope = configProvider.getValue("client-app-scope", String.class);
        this.setProxy(this.configProvider);

        this.privateKeyFile = configProvider.getValue("private-key-file", String.class);
        this.checkFileExtension(privateKeyFile, ".der");

        this.publicCertificateFile = configProvider.getValue("public-certificate-file", String.class);
        this.checkFileExtension(publicCertificateFile, ".cer");

        this.msUrlDomain = configProvider.getValue("ms-url-api-domain", String.class);
    }

    /**
     * This method sets a proxy if proxy values are set in the microprofile config
     * @param configProviderLocal config provider used to get microprofile config values
     */
    public static void setProxy(Config configProviderLocal) {
        Optional<String> proxyHost = configProviderLocal.getOptionalValue("proxy-host", String.class);
        Optional<String> proxyPort = configProviderLocal.getOptionalValue("proxy-port", String.class);

        if (!(proxyHost.isEmpty() && proxyPort.isEmpty())) {
            logger.info("Using the following proxy configuration:");
            logger.info("Proxy host: {}", proxyHost.get());
            logger.info("Proxy port: {}", proxyPort.get());
            System.setProperty("https.proxyHost", proxyHost.get());
            System.setProperty("https.proxyPort", proxyPort.get());
        } else {
            logger.info("Not setting a proxy");
            logger.info("Either proxy host or port not set as a config property");
        }
    }

    /**
     * This method returns the MS OAuth2 token URI
     * @return MS OAuth2 token URI
     */
    public String getMsOAuth2TokenUri() {
        return this.morganStanleyOAuth2TokenUri;
    }

    /**
     * This method returns the client app ID
     * @return client app ID
     */
    public String getClientAppId() {
        return this.clientAppId;
    }

    /**
     * This method returns the client app scope
     * @return client app scope
     */
    public String getClientAppScope() {
        return this.clientAppScope;
    }

    /**
     * This method checks that private/public key files are encoded correctly.
     * @param fileName file name
     * @param requiredExtension expected extension of file
     */
    public void checkFileExtension(String fileName, String requiredExtension) {
        if (!fileName.endsWith(requiredExtension)) {
            if (fileName.endsWith(".pem") && requiredExtension.equals(".der")) {
                logger.error("The private key needs to be encoded and be in .der format.");
                logger.error("Please see the README file on how to do this.");
            }
            throw new IllegalArgumentException("Incorrect file type: " + fileName + ", file type should be " + requiredExtension);
        }
    }

    /**
     * This method reads private key file and return instance of PrivateKey class.
     * @return private key
     * @throws Exception throws exception if file does not exist
     */
    public PrivateKey getPrivateKey() throws Exception {
        Path path = Paths.get(this.privateKeyFile);
        final byte[] bytes = Files.readAllBytes(path);
        final PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(bytes);
        return KeyFactory.getInstance("RSA")
            .generatePrivate(pkcs8EncodedKeySpec);
    }

    /**
     * This method reads public certificate file and returns instance of X509Certificate class.
     * @return public certification
     * @throws Exception throws exception if file does not exist
     */
    public X509Certificate getPublicCertificate() throws Exception {
        Path path = Paths.get(this.publicCertificateFile);
        final FileInputStream fileInputStream = new FileInputStream(path.toFile());
        return (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(fileInputStream);
    }

    /**
     * This method returns the Morgan Stanley api url domain
     * @return msUrlDomain
     */
    public String getMsUrlDomain() {
        return this.msUrlDomain;
    }
}
