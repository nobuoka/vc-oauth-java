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

package info.vividcode.oauth

import java.time.Clock
import java.time.Instant

class OAuthProtocolParametersGenerator<E> constructor(env: E) where E : NextIntEnv {

    private val nonceGenerator = OAuthNonceGenerator(env)

    fun forTemporaryCredentials(clientCredentialIdentifier: String, signatureMethod: String, callbackUrlStr: String, clock: Clock): ParamList {
        return listOf(
                Param("oauth_consumer_key", clientCredentialIdentifier),
                Param("oauth_nonce", nonceGenerator.generateNonceString()),
                Param("oauth_signature_method", signatureMethod),
                Param("oauth_timestamp", Instant.now(clock).epochSecond.toString()),
                Param("oauth_version", "1.0"),
                Param("oauth_callback", callbackUrlStr)
        )
    }

    fun forAccessToken(clientCredentialIdentifier: String, temporaryCredentialIdentifier: String, verifier: String, signatureMethod: String, clock: Clock): ParamList {
        return listOf(
                Param("oauth_consumer_key", clientCredentialIdentifier),
                Param("oauth_token", temporaryCredentialIdentifier),
                Param("oauth_nonce", nonceGenerator.generateNonceString()),
                Param("oauth_signature_method", signatureMethod),
                Param("oauth_timestamp", Instant.now(clock).epochSecond.toString()),
                Param("oauth_version", "1.0"),
                Param("oauth_verifier", verifier)
        )
    }

    fun forNormalRequest(clientIdentifier: String, tokenIdentifier: String, signatureMethod: String, clock: Clock): ParamList {
        val s: ProtocolParameterSet? = null
        s?.get(ProtocolParameter.ConsumerKey)?.name?.toString()
        println(ProtocolParameter.ConsumerKey)

        return listOf(
                Param("oauth_consumer_key", clientIdentifier),
                Param("oauth_token", tokenIdentifier),
                Param("oauth_nonce", nonceGenerator.generateNonceString()),
                Param("oauth_signature_method", signatureMethod),
                Param("oauth_timestamp", Instant.now(clock).epochSecond.toString()),
                Param("oauth_version", "1.0")
        )
    }

}

fun main(args: Array<String>) {
    ProtocolParameterSet.Builder()
            .add(ProtocolParameter.ConsumerKey(""))
            .add(ProtocolParameter.Nonce(""))
            .add(ProtocolParameter.SignatureMethod.HmacSha1)
    println(ProtocolParameter.ConsumerKey)
}
