/*
 * Copyright 2022 EPAM Systems, Inc. (https://www.epam.com/)
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

package com.epam.pipeline.acl.preprocessing;

import com.epam.pipeline.controller.vo.preprocessing.SampleSheetRegistrationVO;
import com.epam.pipeline.manager.preprocessing.NgsPreprocessingManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class NgsPreprocessingApiService {

    @Autowired
    private NgsPreprocessingManager preprocessingManager;

    @PreAuthorize("hasRole('ADMIN') OR hasPermission(#registrationVO.folderId, "
            + "'com.epam.pipeline.entity.pipeline.Folder', 'WRITE'))")
    public void registerSampleSheet(final SampleSheetRegistrationVO registrationVO) {
        preprocessingManager.registerSampleSheet(registrationVO);
    }

    @PreAuthorize("hasRole('ADMIN') OR hasPermission(#folderId, 'com.epam.pipeline.entity.pipeline.Folder', 'WRITE')")
    public void deleteSampleSheet(final Long folderId, final Long machineRunId) {
        preprocessingManager.deleteSampleSheet(folderId, machineRunId);
    }

}
