/*
 * Copyright 2017-2021 EPAM Systems, Inc. (https://www.epam.com/)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.epam.pipeline.manager.quota.handler;

import com.epam.pipeline.dto.quota.QuotaActionType;
import com.epam.pipeline.dto.quota.AppliedQuota;
import com.epam.pipeline.manager.notification.NotificationManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class NotificationQuotaHandler implements QuotaHandler {

    private final NotificationManager notificationManager;

    @Override
    public QuotaActionType type() {
        return QuotaActionType.NOTIFY;
    }

    @Override
    public void applyActionType(final AppliedQuota appliedQuota, final QuotaActionType type) {
        log.debug("Sending exceeded quota notification...");
        notificationManager.notifyOnBillingQuotaExceeding(appliedQuota);
    }
}
