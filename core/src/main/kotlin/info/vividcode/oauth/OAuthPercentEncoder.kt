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

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * The OAuth 1.0 Protocol の仕様に合う形で文字列をパーセントエンコードする機能を提供するクラス。
 */
object OAuthPercentEncoder {

    /** "0123456789ABCDEF" の ASCII バイト列  */
    private val BS = byteArrayOf(48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70)

    /** 指定のバイトをパーセントエンコードする必要があるかどうかの真理値を格納した配列
     * (インデックスがバイト値に対応. ただし最上位ビットが 1 のものは含まない)  */
    private val NEED_ENCODE = BooleanArray(0x7F + 1)
    // NEED_ENCODING の初期化
    init {
        for (i in NEED_ENCODE.indices) {
            // a(97)-z(122), A(65)-Z(90), 0(48)-9(57), -(45), .(46), _(95), ~(126)
            NEED_ENCODE[i] = !(i in 65..90 || i in 97..122 || i in 48..57 || i == 45 || i == 46 || i == 95 || i == 126)
        }
    }

    /**
     * The OAuth 1.0 Protocol の仕様に合う形で文字列をパーセントエンコードする.
     * パーセントエンコードの対象になるのは 'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', '~' を除く全ての文字である.
     *
     * @param str パーセントエンコードの対象文字列
     * @return str をパーセントエンコードした文字列
     */
    @JvmStatic
    fun encode(str: String): String = encode(str.toByteArray(StandardCharsets.UTF_8))

    @JvmStatic
    fun encode(bytes: ByteArray): String =
            ByteArrayOutputStream().use { os ->
                bytes.forEach {
                    val b = it.toInt()
                    if (it < 0 || NEED_ENCODE[b]) {
                        // "%"
                        os.write(37)
                        // 上の 4 ビット
                        os.write(BS[b shr 4 and 0x0F].toInt())
                        // 下の 4 ビット
                        os.write(BS[b and 0x0F].toInt())
                    } else {
                        os.write(b)
                    }
                }
                os.toString()
            }

}
