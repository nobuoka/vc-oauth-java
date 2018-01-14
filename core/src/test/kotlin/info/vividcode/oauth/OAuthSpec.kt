/*
Copyright 2017 Nobuoka Yu

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

import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.*
import java.net.URL
import kotlin.test.assertEquals

object OAuthSpec : Spek({
    describe("signature generation with HMAC-SHA1 (section 9.2)") {
        data class Parameters(val consumerSecret: String, val tokenSecret: String, val baseString: String)

        // Test cases from http://wiki.oauth.net/w/page/12238556/TestCases
        listOf(
                Parameters("cs", "", "bs") to "egQqG5AJep5sJ7anhXju1unge2I=",
                Parameters("cs", "ts", "bs") to "VZVjXceV7JgPq/dOTnNmEfO0Fv8=",
                Parameters(
                        "kd94hf93k423kf44",
                        "pfkkdhi9sl3r4s00",
                        "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
                ) to "tR3+Ty81lMeYAr/Fid0kMTYa/WM="
        ).forEach {
            on("passing parameter `${it.first}`") {
                it("should be generate `${it.second}`") {
                    assertEquals(it.second, OAuthSignatures.makeSignatureWithHmacSha1(
                            "${it.first.consumerSecret}&${it.first.tokenSecret}", it.first.baseString))
                }
            }
        }
    }

    describe("parameter encoding (section 5.1)") {
        // Test cases from http://wiki.oauth.net/w/page/12238556/TestCases
        listOf(
                "abcABC123" to "abcABC123",
                "-._~" to "-._~",
                "%" to "%25",
                "+" to "%2B",
                "&=*" to "%26%3D%2A",
                "\u000A" to "%0A", // LF
                "\u0020" to "%20", // Space
                "\u007F" to "%7F",
                "\u0080" to "%C2%80",
                "\u3001" to "%E3%80%81"
        ).forEach {
            on("passing parameter `${it.first}`") {
                it("should be generate `${it.second}`") {
                    assertEquals(it.second, OAuthPercentEncoder.encode(it.first))
                }
            }
        }
    }

    // See : https://tools.ietf.org/html/rfc5849#section-3.4.1.2 (3.4.1.2.  Base String URI)
    describe("generation of URL base string from URL") {
        fun testBody(expectedUrl: String, testUrl: URL): TestBody.() -> Unit = {
            val actual = OAuth.generateBaseStringUri(testUrl)
            assertEquals(expectedUrl, actual)
        }

        on("passing simple URL (without query string)") {
            val testUrl = URL("http://example.com/test/name")
            val expectedUrl = "http://example.com/test/name"
            it("should generate same URL string", testBody(expectedUrl, testUrl))
        }

        on("passing normal URL with query string") {
            val testUrl = URL("http://example.com/test/name?p=1&p=2")
            val expectedUrl = "http://example.com/test/name"
            it("should generate URL string without query string", testBody(expectedUrl, testUrl))
        }

        on("passing URL with host name in capital case") {
            val testUrl = URL("http://EXAMPLE.COM/test/name?p=1&p=2")
            val expectedUrl = "http://example.com/test/name"
            it("should generate URL string with host name in lowercase", testBody(expectedUrl, testUrl))
        }

        on("passing URL with port number") {
            run {
                val testUrl = URL("http://example.com:80/test/name?p=1&p=2")
                val expectedUrl = "http://example.com/test/name"
                it("should generate URL string without port number if it's default port", testBody(expectedUrl, testUrl))
            }
            run {
                val testUrl = URL("http://example.com:8080/test/name?p=1&p=2")
                val expectedUrl = "http://example.com:8080/test/name"
                it("should generate URL string with port number unless it's default port", testBody(expectedUrl, testUrl))
            }
        }
    }
})
