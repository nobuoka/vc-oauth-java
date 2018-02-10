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

import java.nio.charset.StandardCharsets
import java.time.Clock

interface NextIntEnv { val nextInt: (Int) -> Int }
interface ClockEnv { val clock: Clock }

class OAuthNonceGenerator<E> constructor(private val env: E) where E : NextIntEnv {

    private val NONCE_SEED_BYTES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            .toByteArray(StandardCharsets.US_ASCII)

    /**
     * OAuth 認証に用いる nonce 文字列を生成する.
     * @return 長さ 16 の nonce 文字列
     */
    fun generateNonceString(): String = getNonceString(16)

    /**
     * OAuth 認証に用いる nonce 文字列を, 指定の長さで生成する.
     * @param length 生成する nonce 文字列の長さ
     * @return 生成した nonce 文字列
     */
    fun getNonceString(length: Int): String {
        val bytes = ByteArray(length)
        for (i in 0 until length) {
            bytes[i] = NONCE_SEED_BYTES[env.nextInt(NONCE_SEED_BYTES.size)]
        }
        return String(bytes, StandardCharsets.US_ASCII)
    }

}
