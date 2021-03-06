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

package info.vividcode.oauth.client.tools;

import java.net.URL;

public interface HttpRequestHandler<T> {

    String getRequestMethod(T req);

    URL getUrl(T req);

    String getContentType(T req);

    /**
     * Return a request body of a specified HTTP request.
     * This method is called only in the case the {@link #getContentType(Object)} method
     * returns {@code "application/x-www-form-urlencoded"}.
     *
     * @param req Target HTTP request.
     * @return A request body.
     */
    String getRequestBody(T req);

    void setAuthorizationHeader(T req, String headerValue);

}
