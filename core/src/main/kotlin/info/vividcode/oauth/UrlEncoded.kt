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

/**
 * @author NOBUOKA Yu
 */
internal object UrlEncoded {

    fun decode(s: String): ByteArray {
        val out = ByteArrayOutputStream()
        var pos = 0
        while (pos < s.length) {
            val c = s[pos]
            when (c) {
                '+' -> out.write(0x20)
                '%' -> {
                    val upperHex: Char
                    val lowerHex: Char
                    try {
                        upperHex = s[++pos]
                        lowerHex = s[++pos]
                    } catch (ex: IndexOutOfBoundsException) {
                        throw IllegalArgumentException()
                    }

                    val d = (parseHex(upperHex) * 0x10 + parseHex(lowerHex)).toByte()
                    out.write(d.toInt())
                }
                else -> out.write(c.toByte().toInt())
            }
            pos++
        }
        return out.toByteArray()
    }

    private fun parseHex(c: Char): Byte {
        return if (c in '0'..'9') {
            (c - '0').toByte()
        } else if (c in 'A'..'F') {
            (c - 'A' + 10).toByte()
        } else if (c in 'a'..'f') {
            (c - 'a' + 10).toByte()
        } else {
            throw IllegalArgumentException()
        }
    }

}
