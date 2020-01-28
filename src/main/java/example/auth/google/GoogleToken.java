package example.auth.google;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.GenericData;
import com.google.auth.oauth2.ServiceAccountCredentials;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;

public class GoogleToken {
    public static final String credFile = "path/cred.json";
    public static final String target_audience = "393211549928-c0iacl02ns4lnvpbdgie5f4c9scdiffn.apps.googleusercontent.com";
    public static final String OAUTH_TOKEN_URI = "https://www.googleapis.com/oauth2/v4/token";
    public static final String JWT_BEARER_TOKEN_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    private String getSignedJwt() throws IOException {
        ServiceAccountCredentials sac = ServiceAccountCredentials.fromStream(new FileInputStream(credFile));

        long now = System.currentTimeMillis();
        RSAPrivateKey privateKey = (RSAPrivateKey) sac.getPrivateKey();
        Algorithm algorithm = Algorithm.RSA256(null, privateKey);
        return JWT.create()
                .withKeyId(sac.getPrivateKeyId())
                .withIssuer(sac.getClientEmail())
                .withSubject(sac.getClientEmail())
                .withAudience(OAUTH_TOKEN_URI)
                .withIssuedAt(new Date(now))
                .withExpiresAt(new Date(now + 36000))
                .withClaim("target_audience", target_audience)
                .sign(algorithm);
    }

    public DecodedJWT getGoogleIdToken() throws IOException {
        String jwt = getSignedJwt();
        System.out.println("JWT: "+jwt);
        final GenericData tokenRequest = new GenericData()
                .set("grant_type", JWT_BEARER_TOKEN_GRANT_TYPE)
                .set("assertion", jwt);
        final UrlEncodedContent content = new UrlEncodedContent(tokenRequest);

        HttpTransport httpTransport = new NetHttpTransport();

        final HttpRequestFactory requestFactory = httpTransport.createRequestFactory();

        final HttpRequest request = requestFactory
                .buildPostRequest(new GenericUrl(OAUTH_TOKEN_URI), content)
                .setParser(new JsonObjectParser(JacksonFactory.getDefaultInstance()));

        HttpResponse response = request.execute();
        GenericData responseData = response.parseAs(GenericData.class);
        String idToken = (String) responseData.get("id_token");
        return JWT.decode(idToken);
    }
}
