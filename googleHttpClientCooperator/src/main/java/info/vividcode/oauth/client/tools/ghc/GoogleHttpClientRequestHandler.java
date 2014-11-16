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

package info.vividcode.oauth.client.tools.ghc;

import info.vividcode.oauth.client.tools.HttpRequestHandler;

import java.net.URL;
import java.util.Arrays;

import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpRequest;

public class GoogleHttpClientRequestHandler implements HttpRequestHandler<HttpRequest> {

    @Override
    public String getRequestMethod(HttpRequest req) {
        return req.getRequestMethod();
    }

    @Override
    public URL getUrl(HttpRequest req) {
        return req.getUrl().toURL();
    }

    @Override
    public String getContentType(HttpRequest req) {
        return req.getHeaders().getContentType();
    }

    @Override
    public String getRequestBody(HttpRequest req) {
        HttpContent cont = req.getContent();
        return (cont != null ? cont.toString() : null);
    }

    @Override
    public void setAuthorizationHeader(HttpRequest target, String headerValue) {
        target.getHeaders().setAuthorization(Arrays.asList(headerValue));
    }

}
