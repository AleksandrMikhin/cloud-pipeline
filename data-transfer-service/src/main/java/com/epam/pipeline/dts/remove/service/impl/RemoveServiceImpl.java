/*
 * Copyright 2017-2022 EPAM Systems, Inc. (https://www.epam.com/)
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

package com.epam.pipeline.dts.remove.service.impl;

import com.epam.pipeline.dts.remove.model.RemoveTask;
import com.epam.pipeline.dts.remove.service.RemoveTaskService;
import com.epam.pipeline.dts.remove.service.RemoveService;
import com.epam.pipeline.dts.transfer.model.StorageItem;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class RemoveServiceImpl implements RemoveService {

    private final RemoveTaskService taskService;

    @Override
    public RemoveTask schedule(@NonNull StorageItem target,
                               List<String> included) {
        return taskService.create(target, included);
    }
}
