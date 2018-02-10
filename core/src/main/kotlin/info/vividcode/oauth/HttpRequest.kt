package info.vividcode.oauth

import java.net.URL

data class HttpRequest(
        val method: String,
        val url: URL,
        val wwwFormUrlEncodedRequestBody: String? = null
)
