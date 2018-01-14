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

import java.util.*

/**
 * リクエスト時に送信する単一のパラメータを表すクラス.
 */
typealias Param = Pair<String, String>
val Param.key: String
    get() = this.first
val Param.value: String
    get() = this.second

/**
 * パラメータ (Param オブジェクト) のリストを表すクラス.
 * 実装としては ArrayList<Param></Param> であり,
 * パラメータの追加を行いやすいように 2 次元の
 * String 型配列を受け取るコンストラクタと addAll メソッドが追加されている.
 *
 * @author nobuoka
 */
typealias ParamList = List<Param>

/**
 * パラメータ同士の比較を行うためのクラス.
 * OAuth 認証では, パラメータを並べ替える必要があり,
 * その際にこのクラスのインスタンスを使用する
 */
object ParamComparator : Comparator<Param> {
    override fun compare(o1: Param, o2: Param): Int =
            o1.key.compareTo(o2.key).let {
                if (it == 0) {
                    o1.value.compareTo(o2.value)
                } else {
                    it
                }
            }
}
