/*
 * Copyright 2017-2019 EPAM Systems, Inc. (https://www.epam.com/)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.epam.pipeline.controller.proxy;

import com.epam.lifescience.security.entity.jwt.JWTRawToken;
import com.epam.pipeline.controller.Result;
import com.epam.pipeline.manager.security.AuthManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProxyController {
    private AuthManager authManager;

    @Autowired
    public ProxyController(AuthManager authManager) {
        this.authManager = authManager;
    }

    @GetMapping("/proxy/token")
    public Result<JWTRawToken> getProxyToken() {
        return Result.success(authManager.issueTokenForCurrentUser());
    }
}
