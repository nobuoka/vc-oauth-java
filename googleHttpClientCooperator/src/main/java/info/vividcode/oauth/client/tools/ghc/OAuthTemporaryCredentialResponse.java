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

package info.vividcode.oauth.client.tools.ghc;

import com.google.api.client.util.GenericData;
import com.google.api.client.util.Key;

public class OAuthTemporaryCredentialResponse extends GenericData {
    @Key("oauth_token")
    public String identifier;
    @Key("oauth_token_secret")
    public String sharedSecret;
    @Key("oauth_callback_confirmed")
    public String callbackConfirmed;
}
