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

import info.vividcode.oauth.OAuthCredentialsHolder;
import info.vividcode.util.oauth.OAuthRequestHelper;
import info.vividcode.util.oauth.OAuthRequestHelper.ParamList;

import java.util.Date;

public class GenericOAuthParamsGenerator implements OAuthParamsGenerator {

    @Override
    public ParamList generate(OAuthCredentialsHolder auth, String signatureMethod) {
        return OAuthRequestHelper.ParamList.fromArray(
            new String[][]{
                    { "oauth_consumer_key", auth.getClientIdentifier() },
                    { "oauth_token", auth.getTokenIdentifier() },
                    { "oauth_nonce", OAuthRequestHelper.generateNonce() },
                    { "oauth_signature_method", signatureMethod },
                    { "oauth_timestamp", Long.toString(new Date().getTime() / 1000) },
                    { "oauth_version", "1.0" },
                  } );
    }

}
