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

package info.vividcode.oauth.protocol

import java.nio.charset.StandardCharsets
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object Signatures {

    private val US_ASCII = StandardCharsets.US_ASCII

    /**
     * See [RFC 5849, section 3.4.2](https://tools.ietf.org/html/rfc5849#section-3.4.2).
     *
     * @param text The signature base string from RFC 5849, Section 3.4.1.1.
     * @param key TODO
     * @return TODO
     */
    @JvmStatic
    fun makeSignatureWithHmacSha1(key: String, text: String): String {
        // Every implementation of the Java platform is required to support HmacSHA1.
        val algorithmName = "HmacSHA1"
        val mac: Mac = try {
            Mac.getInstance(algorithmName)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        }

        val k = SecretKeySpec(key.toByteArray(US_ASCII), algorithmName)
        try {
            mac.init(k)
        } catch (e: InvalidKeyException) {
            throw RuntimeException(e)
        }

        val digest = mac.doFinal(text.toByteArray(US_ASCII))
        return Base64.getEncoder().encodeToString(digest)
    }

}
