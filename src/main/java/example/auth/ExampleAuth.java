package example.auth;

import com.auth0.jwt.interfaces.DecodedJWT;
import example.auth.google.GoogleToken;
import java.io.IOException;

public class ExampleAuth {
    public static void main(String[] args) throws IOException {
        GoogleToken googleToken = new GoogleToken();
        DecodedJWT token = googleToken.getGoogleIdToken();
        System.out.println(token.getToken());
    }
}
