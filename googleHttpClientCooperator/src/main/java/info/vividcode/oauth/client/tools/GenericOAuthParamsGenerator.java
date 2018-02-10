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

import info.vividcode.oauth.NextIntEnv;
import info.vividcode.oauth.OAuthCredentialsHolder;
import info.vividcode.oauth.OAuthProtocolParametersGenerator;
import kotlin.Pair;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.List;

public class GenericOAuthParamsGenerator implements OAuthParamsGenerator {

    static final OAuthProtocolParametersGenerator generator = new OAuthProtocolParametersGenerator<>(new NextIntEnv() {
        private Function1<Integer, Integer> nextInt = new SecureRandom()::nextInt;
        @NotNull
        @Override
        public Function1<Integer, Integer> getNextInt() {
            return nextInt;
        }
    });

    @Override
    public List<Pair<String, String>> generate(OAuthCredentialsHolder auth, String signatureMethod) {
        return generator.forNormalRequest(auth.getClientIdentifier(), auth.getTokenIdentifier(), signatureMethod, Clock.systemDefaultZone());
    }

}
