/*
Copyright 2014, 2017 NOBUOKA Yu

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

import java.time.Clock;
import java.util.List;

public class GenericTokenCredentialOAuthParamsGenerator implements OAuthParamsGenerator {

    private final String mVerifier;

    public GenericTokenCredentialOAuthParamsGenerator(String verifier) {
        mVerifier = verifier;
    }

    @Override
    public List<kotlin.Pair<String, String>> generate(OAuthCredentialsHolder auth, String signatureMethod) {
        return GenericOAuthParamsGenerator.generator.forAccessToken(
                auth.getClientIdentifier(), auth.getTokenIdentifier(), mVerifier, signatureMethod, Clock.systemDefaultZone());
    }

}
