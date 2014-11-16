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

package info.vividcode.oauth.client.tools;

import info.vividcode.oauth.OAuth;
import info.vividcode.oauth.OAuthCredentialsHolder;
import info.vividcode.oauth.OAuthSignature;
import info.vividcode.util.oauth.OAuthEncoder;
import info.vividcode.util.oauth.OAuthRequestHelper.Param;
import info.vividcode.util.oauth.OAuthRequestHelper.ParamList;

import java.net.URL;

public class OAuthRequestAuthorization<T> implements OAuthCredentialsHolder {

    private String mClientIdentifier = "";
    private String mClientSharedSecret = "";

    @Override
    public final String getClientIdentifier() {
        return mClientIdentifier;
    }

    @Override
    public final String getClientSharedSecret() {
        return mClientSharedSecret;
    }

    @Override
    public final void setClientCredential(String identifier, String secret) {
        mClientIdentifier = identifier;
        mClientSharedSecret = secret;
    }

    private String mTokenIdentifier = "";
    private String mTokenSharedSecret = "";

    @Override
    public final String getTokenIdentifier() {
        return mTokenIdentifier;
    }

    @Override
    public final String getTokenSharedSecret() {
        return mTokenSharedSecret;
    }

    @Override
    public final void setTokenCredential(String identifier, String secret) {
        mTokenIdentifier = identifier;
        mTokenSharedSecret = secret;
    }

    private OAuthParamsGenerator mOAuthParamListGenerator;

    public void setOAuthParamsGenerator(OAuthParamsGenerator gen) {
        mOAuthParamListGenerator = gen;
    }

    private HttpRequestHandler<T> mRequestHandler;

    public void setRequestHandler(HttpRequestHandler<T> handler) {
        mRequestHandler = handler;
    }

    public void sign(T req) {
        // OAuth 関係のパラメータ。
        ParamList protocolParams = mOAuthParamListGenerator.generate(this, "HMAC-SHA1");
        // Signature base string の生成。
        String signatureBaseString = generateSignatureBaseString(req, protocolParams);

        String secrets =
                OAuthEncoder.encode(mClientSharedSecret) + '&' +
                OAuthEncoder.encode(mTokenSharedSecret);

        String signature = OAuthSignature.makeSignatureWithHmacSha1(secrets, signatureBaseString);
        protocolParams.add(new Param("oauth_signature", signature));

        mRequestHandler.setAuthorizationHeader(req, getAuthorizationHeaderString(protocolParams, ""));
    }

    private String generateSignatureBaseString(T req, ParamList protocolParams) {
        String method = mRequestHandler.getRequestMethod(req);
        URL url = mRequestHandler.getUrl(req);
        String contentType = mRequestHandler.getContentType(req);
        String reqBody = ("application/x-www-form-urlencoded".equals(contentType) ?
                mRequestHandler.getRequestBody(req) :
                null);
        return OAuth.generateSignatureBaseString(method, url, protocolParams, reqBody);
    }

    private String getAuthorizationHeaderString(ParamList protocolParams, String realm) {
        StringBuilder sb = new StringBuilder();
        sb.append("OAuth realm=\"").append(realm).append('"');
        for (Param p : protocolParams) {
            sb.append(", ");
            sb.append(OAuthEncoder.encode(p.getKey()));
            sb.append("=\"").append(OAuthEncoder.encode(p.getValue())).append('"');
        }
        return sb.toString();
    }

}
