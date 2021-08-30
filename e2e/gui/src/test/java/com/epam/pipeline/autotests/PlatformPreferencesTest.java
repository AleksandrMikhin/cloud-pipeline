/*
 * Copyright 2017-2021 EPAM Systems, Inc. (https://www.epam.com/)
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
package com.epam.pipeline.autotests;

import com.epam.pipeline.autotests.mixins.Navigation;
import com.epam.pipeline.autotests.utils.C;
import com.epam.pipeline.autotests.utils.TestCase;
import com.epam.pipeline.autotests.utils.Utils;
import org.testng.annotations.Test;

public class PlatformPreferencesTest extends AbstractBfxPipelineTest implements Navigation {

    @Test
    @TestCase(value = {""})
    public void checkHelpContent() {
        navigationMenu()
                .settings()
                .switchToPreferences()
                .switchToUserInterface()
                .checkSupportTemplate(C.SUPPORT_CONTENT);
    }

    @Test
    @TestCase(value = {""})
    public void checkLustreMountOption() {
        navigationMenu()
                .settings()
                .switchToPreferences()
                .switchToLustreFS()
                .checkLustreFSMountOptionsValue(C.LUSTRE_MOUNT_OPTIONS);
    }

    @Test
    @TestCase(value = {""})
    public void checkLaunchSystemParameters() {
        final String launchConfig = Utils.readFile(C.LAUNCH_SYSTEM_PARAMETERS_CONFIG_PATH);
        navigationMenu()
                .settings()
                .switchToPreferences()
                .switchToLaunch()
                .checkLaunchSystemParameters(launchConfig);
    }
}
