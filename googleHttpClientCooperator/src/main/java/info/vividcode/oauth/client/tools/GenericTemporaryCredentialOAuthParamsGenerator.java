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

import info.vividcode.oauth.OAuthIdentifiers;
import kotlin.Pair;

import java.time.Clock;
import java.util.List;

public class GenericTemporaryCredentialOAuthParamsGenerator implements OAuthParamsGenerator {

    private final String mCallbackUrlStr;

    public GenericTemporaryCredentialOAuthParamsGenerator(String callbackUrl) {
        mCallbackUrlStr = callbackUrl;
    }

    @Override
    public List<Pair<String, String>> generate(OAuthIdentifiers auth, String signatureMethod) {
        return GenericOAuthParamsGenerator.generator.forTemporaryCredentials(
                auth.getClientIdentifier(), signatureMethod, mCallbackUrlStr, Clock.systemDefaultZone());
    }

}
