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

package info.vividcode.oauth;

import java.io.ByteArrayOutputStream;

/**
 * @author NOBUOKA Yu
 */
class UrlEncoded {

    private static byte parseHex(char c) {
        if ('0' <= c && c <= '9') {
            return (byte) (c - '0');
        } else if ('A' <= c && c <= 'F') {
            return (byte) (c - 'A' + 10);
        } else if ('a' <= c && c <= 'f') {
            return (byte) (c - 'a' + 10);
        } else {
            throw new IllegalArgumentException();
        }
    }

    public static byte[] decode(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int pos = 0;
        while (pos < s.length()) {
            char c = s.charAt(pos);
            switch (c) {
            case '+':
                out.write(0x20);
                break;
            case '%':
                char upperHex, lowerHex;
                try {
                    upperHex = s.charAt(++pos);
                    lowerHex = s.charAt(++pos);
                } catch (IndexOutOfBoundsException ex) {
                    throw new IllegalArgumentException();
                }
                byte d = (byte) (parseHex(upperHex) * 0x10 + parseHex(lowerHex));
                out.write(d);
                break;
            default:
                out.write((byte) c);
                break;
            }
            pos++;
        }
        return out.toByteArray();
    }

}
