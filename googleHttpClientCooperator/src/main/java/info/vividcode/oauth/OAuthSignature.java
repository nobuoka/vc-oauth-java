/*
Copyright 2014 NOBUOKA Yu

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package info.vividcode.oauth;

import info.vividcode.util.Base64Encoder;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class OAuthSignature {

    private static final Charset US_ASCII = Charset.forName("US-ASCII");

    /**
     * See <a href="https://tools.ietf.org/html/rfc5849#section-3.4.2">RFC 5849, section 3.4.2</a>.
     *
     * @param text The signature base string from RFC 5849, Section 3.4.1.1.
     * @param key TODO
     * @return TODO
     */
    public static String makeSignatureWithHmacSha1(String key, String text) {
        final String algorithmName = "HmacSHA1";
        Key k = new SecretKeySpec(key.getBytes(US_ASCII), algorithmName);
        Mac mac;
        try {
            mac = Mac.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            mac.init(k);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        byte[] digest = mac.doFinal(text.getBytes(US_ASCII));
        return Base64Encoder.encode(digest);
    }

}
