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
package com.epam.pipeline.autotests;

import com.epam.pipeline.autotests.ao.SettingsPageAO.PreferencesAO;
import com.epam.pipeline.autotests.ao.SettingsPageAO.UserManagementAO.UsersTabAO;
import com.epam.pipeline.autotests.ao.SystemDictionariesAO;
import com.epam.pipeline.autotests.ao.ToolTab;
import com.epam.pipeline.autotests.mixins.Authorization;
import com.epam.pipeline.autotests.mixins.Tools;
import com.epam.pipeline.autotests.utils.BucketPermission;
import com.epam.pipeline.autotests.utils.C;
import com.epam.pipeline.autotests.utils.TestCase;
import com.epam.pipeline.autotests.utils.Utils;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.text.NumberFormat;
import java.time.LocalDate;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static com.codeborne.selenide.Condition.text;
import static com.codeborne.selenide.Selenide.refresh;
import static com.epam.pipeline.autotests.ao.BillingTabAO.BillingQuotaPeriod;
import static com.epam.pipeline.autotests.ao.BillingTabAO.BillingQuotaPeriod.*;
import static com.epam.pipeline.autotests.ao.BillingTabAO.BillingQuotaType.*;
import static com.epam.pipeline.autotests.ao.BillingTabAO.BillingQuotaStatus.*;
import static com.epam.pipeline.autotests.ao.Primitive.*;
import static com.epam.pipeline.autotests.utils.Privilege.EXECUTE;
import static com.epam.pipeline.autotests.utils.Privilege.READ;
import static com.epam.pipeline.autotests.utils.Privilege.WRITE;
import static com.epam.pipeline.autotests.utils.Utils.DATE_PATTERN;
import static com.epam.pipeline.autotests.utils.Utils.getFile;
import static com.epam.pipeline.autotests.utils.Utils.randomSuffix;
import static java.lang.String.format;
import static java.time.format.DateTimeFormatter.ofPattern;
import static java.util.Locale.ENGLISH;
import static java.util.concurrent.TimeUnit.SECONDS;

public class BillingQuotasTest
        extends AbstractSeveralPipelineRunningTest
        implements Authorization, Tools {

    private final String tool = C.TESTING_TOOL_NAME;
    private final String registry = C.DEFAULT_REGISTRY;
    private final String group = C.DEFAULT_GROUP;
    private final String nfsPrefix = C.NFS_PREFIX;
    private final String ELASTIC_URL = C.ELASTIC_URL;
    private final String ROLE_BILLING_MANAGER = "ROLE_BILLING_MANAGER";
    private final String BILLING_REPORTS_ENABLED_ADMINS = "billing.reports.enabled.admins";
    private final String BILLING_REPORTS_ENABLED = "billing.reports.enabled";
    private final String BILLING_QUOTAS_PERIOD_SECONDS = "billing.quotas.period.seconds";
    private final String LAUNCH_ERROR_MESSAGE =
            "Launch of new compute instances is forbidden due to exceeded billing quota";
    private final int BILLING_QUOTAS_PERIOD = 120;
    private final String TEST_ROLE = "ROLE_ADVANCED_USER";
    private final String USER_GROUP = C.ROLE_USER;
    private final String NOTIFY = "Notify";
    private final String READ_ONLY_MODE = "Read-only mode";
    private final String DISABLE_NEW_JOBS = "Disable new jobs";
    private final String STOP_ALL_JOBS = "Stop all jobs";
    private final String BLOCK = "Block";
    private final String dataStorage = format("billingTestData-%s", randomSuffix());
    private final String testStorage1 = format("testBilling-%s", randomSuffix());
    private final String testStorage2 = format("testBilling-%s", randomSuffix());
    private final String testFsStorage = format("testBilling-%s", randomSuffix());
    private final String importScript = "import_billing_data.py";
    private final String billingData = "billing-test.txt";
    private final String billingCenter1 = "group3";
    private final String billingCenter2 = "group2";
    private final String[] billing = {"70", "80", "100", "80", "90", "120"};
    private final String[] quota = {"10000", "20000", billing[3], billing[4], billing[5], billing[3],
            billing[4], billing[1], billing[1], billing[2], billing[2], billing[0]};
    private final String[] threshold = {"90", "80", "90", "80", "90", "70", "70", "110"};
    private String[] prefQuotasPeriodInitial;
    private boolean[] prefReportsEnabledAdminsInitial;
    private boolean[] prefReportsEnabledInitial;
    private String[] runId = new String[4];
    private String[] storageID = new String[2];
    private String fsStorageID;
    private boolean billingGroupDictionaryExist = true;

    @BeforeClass
    public void setPreferencesValue() {
        final PreferencesAO preferencesAO = navigationMenu()
                .settings()
                .switchToPreferences();
        prefReportsEnabledAdminsInitial = preferencesAO
                .getCheckboxPreferenceState(BILLING_REPORTS_ENABLED_ADMINS);
        preferencesAO
                .setCheckboxPreference(BILLING_REPORTS_ENABLED_ADMINS, true,true)
                .saveIfNeeded();
        prefReportsEnabledInitial = preferencesAO
                .getCheckboxPreferenceState(BILLING_REPORTS_ENABLED);
        preferencesAO
                .setCheckboxPreference(BILLING_REPORTS_ENABLED, true,true)
                .saveIfNeeded();
        prefQuotasPeriodInitial = preferencesAO
                .getLinePreference(BILLING_QUOTAS_PERIOD_SECONDS);
        preferencesAO
                .setPreference(BILLING_QUOTAS_PERIOD_SECONDS, Integer.toString(BILLING_QUOTAS_PERIOD), true)
                .saveIfNeeded();
        createBillingCenter("billing-group", billingCenter1);
        navigationMenu()
                .settings()
                .switchToUserManagement()
                .switchToUsers()
                .searchForUserEntry(user.login)
                .edit()
                .addAttributeWithValueIfNeeded("billing-group", billingCenter1)
                .ok()
                .searchForUserEntry(userWithoutCompletedRuns.login)
                .edit()
                .addRoleOrGroupIfNeeded(TEST_ROLE)
                .ok();
    }

    @BeforeClass
    public void prepareBillingValues() {
        IntStream.range(0, 3)
                .forEach(i -> {
                        runId[i] = launchTool();
                        runsMenu()
                                .stopRunIfPresent(runId[i]);
                });
        library()
                .createStorage(testStorage1)
                .selectStorage(testStorage1);
        storageID[0] = Utils.entityIDfromURL();
        library()
                .createStorage(testStorage2)
                .createStorage(dataStorage)
                .selectStorage(dataStorage);
        storageID[1] = Utils.entityIDfromURL();
        library()
                .createNfsMount(format("/%s", testFsStorage), testFsStorage)
                .selectStorage(testFsStorage);
        fsStorageID = Utils.entityIDfromURL();
        library()
                .selectStorage(dataStorage)
                .uploadFile(getFile(importScript))
                .uploadFile(updateDataBillingFile());
        Stream.of(testStorage1, testStorage2, testFsStorage).forEach(storage -> {
            addAccountToStoragePermissions(user, storage);
            givePermissions(user,
                    BucketPermission.allow(READ, storage),
                    BucketPermission.allow(WRITE, storage),
                    BucketPermission.allow(EXECUTE, storage)
            );
        });
        tools()
                .perform(registry, group, tool, ToolTab::runWithCustomSettings)
                .expandTab(ADVANCED_PANEL)
                .selectDataStoragesToLimitMounts()
                .clearSelection()
                .searchStorage(dataStorage)
                .selectStorage(dataStorage)
                .ok()
                .launch(this)
                .showLog(runId[3] = getLastRunId())
                .waitForSshLink()
                .ssh(shell -> shell
                        .waitUntilTextAppears(runId[3])
                        .execute(format("cd /cloud-data/%s", dataStorage.toLowerCase()))
                        .execute(format("python %s --operation add --data-file %s --elastic-url %s", importScript,
                                billingData, ELASTIC_URL))
                        .waitForLog(format("root@pipeline-%s:~/cloud-data/%s#", runId[3], dataStorage.toLowerCase()))
                        .close());
    }

    @AfterClass(alwaysRun=true)
    public void resetPreferencesValue() {
        logoutIfNeeded();
        loginAs(admin);
        final PreferencesAO preferencesAO = navigationMenu()
                .settings()
                .switchToPreferences();
        preferencesAO
                .setCheckboxPreference(BILLING_REPORTS_ENABLED_ADMINS,
                        prefReportsEnabledAdminsInitial[0],prefReportsEnabledAdminsInitial[1])
                .saveIfNeeded();
        preferencesAO
                .setCheckboxPreference(BILLING_REPORTS_ENABLED,
                        prefReportsEnabledInitial[0],prefReportsEnabledInitial[1])
                .saveIfNeeded();
        preferencesAO
                .setPreference(BILLING_QUOTAS_PERIOD_SECONDS,
                        prefQuotasPeriodInitial[0], Boolean.parseBoolean(prefQuotasPeriodInitial[1]))
                .saveIfNeeded();
        runsMenu()
                .showLog(runId[3])
                .waitForSshLink()
                .ssh(shell -> shell
                        .waitUntilTextAppears(runId[3])
                        .execute(format("cd /cloud-data/%s", dataStorage.toLowerCase()))
                        .execute(format("python %s --operation remove --data-file %s --elastic-url %s", importScript,
                                billingData, ELASTIC_URL))
                        .waitForLog(format("root@pipeline-%s:~/cloud-data/%s#", runId[3], dataStorage.toLowerCase()))
                        .close());
        deleteBillingCenter("billing-group", billingCenter1);
    }

    @AfterClass(alwaysRun=true)
    public void removeEntities() {
        Utils.removeStorages(this, testStorage1, testStorage2, dataStorage);
        library()
                .selectStorage(testFsStorage)
                .clickEditStorageButton()
                .editForNfsMount()
                .clickDeleteStorageButton()
                .clickDelete();
    }

    @Test
    @TestCase(value = {"762_1"})
    public void checkGlobalQuotaCreation() {
        try {
            logout();
            loginAs(user)
                    .settings()
                    .switchToMyProfile()
                    .validateUserName(user.login);
            navigationMenu()
                    .checkBillingVisible(true)
                    .billing()
                    .ensureNotVisible(QUOTAS, STORAGES, COMPUTE_INSTANCES);
            logout();
            loginAs(admin)
                    .settings()
                    .switchToUserManagement()
                    .switchToUsers()
                    .searchForUserEntry(user.login)
                    .edit()
                    .addRoleOrGroup(ROLE_BILLING_MANAGER)
                    .sleep(2, SECONDS)
                    .ok();
            logout();
            loginAs(user)
                    .settings()
                    .switchToMyProfile()
                    .validateUserName(user.login);
            navigationMenu()
                    .checkBillingVisible(true)
                    .billing()
                    .ensureVisible(QUOTAS, STORAGES, COMPUTE_INSTANCES)
                    .click(QUOTAS)
                    .getQuotasSection(OVERALL)
                    .addQuota()
                    .ensureVisible(QUOTA, ACTIONS, THRESHOLD)
                    .ensure(PERIOD, text(PER_MONTH.period))
                    .ensureNotVisible(RECIPIENTS)
                    .ensureDisable(SAVE)
                    .setValue(QUOTA, quota[0])
                    .ensureActionsList(NOTIFY, READ_ONLY_MODE, DISABLE_NEW_JOBS,
                            STOP_ALL_JOBS, BLOCK)
                    .setAction(threshold[0], NOTIFY)
                    .ensureVisible(RECIPIENTS)
                    .addRecipient(user.login)
                    .ok()
                    .openQuotaEntry("", quotaEntry(quota[0], PER_MONTH))
                    .ensure(TITLE, text("Global quota"))
                    .ensureDisable(QUOTA, THRESHOLD)
                    .ensureComboboxFieldDisabled(ACTIONS, PERIOD, RECIPIENTS)
                    .ensureNotVisible(SAVE)
                    .ensureVisible(CLOSE, REMOVE)
                    .close()
                    .getQuotaEntry("", quotaEntry(quota[0], PER_MONTH))
                    .checkEntryActions(format("%s%%: %s", threshold[0], NOTIFY.toLowerCase()));
        } finally {
            refresh();
            logout();
            loginAs(admin)
                    .settings()
                    .switchToUserManagement()
                    .switchToUsers()
                    .searchForUserEntry(user.login)
                    .edit()
                    .deleteRoleOrGroup(ROLE_BILLING_MANAGER)
                    .sleep(2, SECONDS)
                    .ok();
        }
    }

    @Test(dependsOnMethods = "checkGlobalQuotaCreation")
    @TestCase(value = {"762_2"})
    public void checkCreationDeletionGlobalQuotaWithTheSameAndDifferentQuotaPeriod() {
        String message1 = format("Global monthly expenses quota %s$. Actions: %s%% Notify", quota[0], threshold[0]);
        String message2 = format("Global annual expenses quota %s$. Actions: %s%% Notify", quota[1], threshold[1]);
        billingMenu()
                .click(QUOTAS)
                .getQuotasSection(OVERALL)
                .addQuota()
                .setValue(QUOTA, quota[1])
                .setAction(threshold[1], NOTIFY, READ_ONLY_MODE)
                .addRecipient(admin.login)
                .click(SAVE)
                .errorMessageShouldAppear(OVERALL, PER_MONTH)
                .selectValue(PERIOD, PER_YEAR.period)
                .ok()
                .sleep(BILLING_QUOTAS_PERIOD, SECONDS)
                .refresh()
                .getQuotaEntry("", quotaEntry(quota[0], PER_MONTH))
                .checkQuotaStatus(GREEN);
        checkQuotasExceededWarningForUser(user, message1, message2);
        billingMenu()
                .click(QUOTAS)
                .getQuotasSection(OVERALL)
                .openQuotaEntry("", quotaEntry(quota[0], PER_MONTH))
                .removeQuota()
                .getQuotaEntry("", quotaEntry(quota[1], PER_YEAR))
                .checkQuotaStatus(YELLOW)
                .removeQuota();
    }

    @Test
    @TestCase(value = {"762_3"})
    public void checkOverallComputeInstancesQuota() {
        billingMenu()
                .click(COMPUTE_INSTANCES)
                .checkQuotasSections(OVERALL, BILLING_CENTERS, GROUPS, USERS)
                .getQuotasSection(OVERALL)
                .addQuota()
                .ensure(TITLE, text("Create compute instances quota"))
                .setValue(QUOTA, quota[2])
                .selectValue(PERIOD, PER_YEAR.period)
                .ensureActionsList(NOTIFY, DISABLE_NEW_JOBS, STOP_ALL_JOBS, BLOCK)
                .setAction(threshold[2], NOTIFY)
                .addRecipient(admin.login)
                .ok()
                .sleep(BILLING_QUOTAS_PERIOD, SECONDS)
                .refresh()
                .getQuotaEntry("", quotaEntry(quota[2], PER_YEAR))
                .checkQuotaStatus(YELLOW)
                .checkEntryActions(format("%s%%: %s", threshold[0], NOTIFY.toLowerCase()))
                .checkQuotaWarning()
                .removeQuota();
    }

    @Test
    @TestCase(value = {"762_4"})
    public void checkGroupsComputeInstancesQuota() {
        String message1 = format("Billing center %s: compute quarterly expenses quota %s$. Actions: %s%% Disable new jobs", billingCenter1, quota[4], threshold[4]);
        String message2 = format("User %s: compute annual expenses quota %s$. Actions: %s%% Notify", user.login, quota[5], threshold[4]);
        logout();
        loginAs(user);
        String nonAdminRunId = launchTool();
        logout();
        loginAs(admin);
        String adminRunId = launchTool();

        billingMenu()
                .click(COMPUTE_INSTANCES)
                .getQuotasSection(BILLING_CENTERS)
                .addQuota()
                .ensureVisible(QUOTA, ACTIONS, THRESHOLD, BILLING_CENTER)
                .ensure(PERIOD, text(PER_MONTH.period))
                .ensureNotVisible(RECIPIENTS)
                .ensureDisable(SAVE)
                .addQuotaObject(BILLING_CENTER, billingCenter1)
                .setValue(QUOTA, quota[4])
                .selectValue(PERIOD, PER_QUARTER.period)
                .ensureActionsList(NOTIFY, DISABLE_NEW_JOBS, STOP_ALL_JOBS, BLOCK)
                .setAction(threshold[4], DISABLE_NEW_JOBS)
                .ok()
                .getQuotaEntry(billingCenter1, quotaEntry(quota[4], PER_QUARTER))
                .checkEntryActions(format("%s%%: %s", threshold[4], DISABLE_NEW_JOBS.toLowerCase()));
        billingMenu()
                .click(COMPUTE_INSTANCES)
                .getQuotasSection(USERS)
                .addQuota()
                .ensureVisible(QUOTA, ACTIONS, THRESHOLD, USER_NAME)
                .ensure(PERIOD, text(PER_MONTH.period))
                .ensureDisable(SAVE)
                .addQuotaObject(USER_NAME, user.login)
                .setValue(QUOTA, quota[5])
                .selectValue(PERIOD, PER_YEAR.period)
                .ensureActionsList(NOTIFY, DISABLE_NEW_JOBS, STOP_ALL_JOBS, BLOCK)
                .setAction(threshold[4], STOP_ALL_JOBS)
                .ok()
                .sleep(BILLING_QUOTAS_PERIOD, SECONDS)
                .refresh()
                .getQuotaEntry(user.login, quotaEntry(quota[5], PER_YEAR))
                .checkQuotaStatus(RED)
                .checkEntryActions(format("%s%%: %s", threshold[4], STOP_ALL_JOBS.toLowerCase()))
                .checkQuotaWarning();
        billingMenu()
                .click(COMPUTE_INSTANCES)
                .getQuotasSection(BILLING_CENTERS)
                .getQuotaEntry(billingCenter1, quotaEntry(quota[4], PER_QUARTER))
                .checkQuotaStatus(RED)
                .checkQuotaWarning();

        logout();
        loginAs(user)
                .runs()
                .completedRuns()
                .shouldContainRun("pipeline", nonAdminRunId);
        tools()
                .perform(registry, group, tool, ToolTab::runWithCustomSettings)
                .launchWithError(LAUNCH_ERROR_MESSAGE);
        checkQuotasExceededWarningForUser(user, message1, message2);
        logout();
        loginAs(admin)
                .runs()
                .showLog(adminRunId)
                .waitForSshLink()
                .ssh(shell -> shell
                        .waitUntilTextAppears(adminRunId)
                        .execute(format("pipe run -di %s -u %s",
                                tool, user.login))
                        .waitForLog("Error: Failed to fetch data from server. " +
                                "Server responded with message: Launch of new compute instances " +
                                "is forbidden due to exceeded billing quota.")
                        .close());

        billingMenu()
                .click(COMPUTE_INSTANCES)
                .getQuotasSection(BILLING_CENTERS)
                .getQuotaEntry(billingCenter1, quotaEntry(quota[4], PER_QUARTER))
                .removeQuota();
        billingMenu()
                .click(COMPUTE_INSTANCES)
                .getQuotasSection(USERS)
                .getQuotaEntry(user.login, quotaEntry(quota[5], PER_YEAR))
                .removeQuota();
    }

    @Test
    @TestCase(value = {"762_5"})
    public void checkBillingCenterAndUsersComputeInstancesQuota() {
        String message1 = format("Billing center %s: compute quarterly expenses quota %s$. Actions: %s%% Disable new jobs", billingCenter1, quota[4], threshold[4]);
        String message2 = format("User %s: compute annual expenses quota %s$. Actions: %s%% Notify", user.login, quota[5], threshold[4]);
        logout();
        loginAs(user);
        String nonAdminRunId = launchTool();
        logout();
        loginAs(admin);
        String adminRunId = launchTool();

        billingMenu()
                .click(COMPUTE_INSTANCES)
                .getQuotasSection(BILLING_CENTERS)
                .addQuota()
                .ensureVisible(QUOTA, ACTIONS, THRESHOLD, BILLING_CENTER)
                .ensure(PERIOD, text(PER_MONTH.period))
                .ensureNotVisible(RECIPIENTS)
                .ensureDisable(SAVE)
                .addQuotaObject(BILLING_CENTER, billingCenter1)
                .setValue(QUOTA, quota[4])
                .selectValue(PERIOD, PER_QUARTER.period)
                .ensureActionsList(NOTIFY, DISABLE_NEW_JOBS, STOP_ALL_JOBS, BLOCK)
                .setAction(threshold[4], DISABLE_NEW_JOBS)
                .ok()
                .getQuotaEntry(billingCenter1, quotaEntry(quota[4], PER_QUARTER))
                .checkEntryActions(format("%s%%: %s", threshold[4], DISABLE_NEW_JOBS.toLowerCase()));
        billingMenu()
                .click(COMPUTE_INSTANCES)
                .getQuotasSection(USERS)
                .addQuota()
                .ensureVisible(QUOTA, ACTIONS, THRESHOLD, USER_NAME)
                .ensure(PERIOD, text(PER_MONTH.period))
                .ensureDisable(SAVE)
                .addQuotaObject(USER_NAME, user.login)
                .setValue(QUOTA, quota[5])
                .selectValue(PERIOD, PER_YEAR.period)
                .ensureActionsList(NOTIFY, DISABLE_NEW_JOBS, STOP_ALL_JOBS, BLOCK)
                .setAction(threshold[4], STOP_ALL_JOBS)
                .ok()
                .sleep(BILLING_QUOTAS_PERIOD, SECONDS)
                .refresh()
                .getQuotaEntry(user.login, quotaEntry(quota[5], PER_YEAR))
                .checkQuotaStatus(RED)
                .checkEntryActions(format("%s%%: %s", threshold[4], STOP_ALL_JOBS.toLowerCase()))
                .checkQuotaWarning();
        billingMenu()
                .click(COMPUTE_INSTANCES)
                .getQuotasSection(BILLING_CENTERS)
                .getQuotaEntry(billingCenter1, quotaEntry(quota[4], PER_QUARTER))
                .checkQuotaStatus(RED)
                .checkQuotaWarning();

        logout();
        loginAs(user)
                .runs()
                .completedRuns()
                .shouldContainRun("pipeline", nonAdminRunId);
        tools()
                .perform(registry, group, tool, ToolTab::runWithCustomSettings)
                .launchWithError(LAUNCH_ERROR_MESSAGE);
        checkQuotasExceededWarningForUser(user, message1, message2);
        logout();
        loginAs(admin)
                .runs()
                .showLog(adminRunId)
                .waitForSshLink()
                .ssh(shell -> shell
                        .waitUntilTextAppears(adminRunId)
                        .execute(format("pipe run -di %s -u %s",
                                tool, user.login))
                        .waitForLog("Error: Failed to fetch data from server. " +
                                "Server responded with message: Launch of new compute instances " +
                                "is forbidden due to exceeded billing quota.")
                        .close());

        billingMenu()
                .click(COMPUTE_INSTANCES)
                .getQuotasSection(BILLING_CENTERS)
                .getQuotaEntry(billingCenter1, quotaEntry(quota[4], PER_QUARTER))
                .removeQuota();
        billingMenu()
                .click(COMPUTE_INSTANCES)
                .getQuotasSection(USERS)
                .getQuotaEntry(user.login, quotaEntry(quota[5], PER_YEAR))
                .removeQuota();
    }

    @Test
    @TestCase(value = {"762_6"})
    public void checkOverallStoragesQuota() {
        billingMenu()
                .click(STORAGES)
                .checkQuotasSections(OVERALL, BILLING_CENTERS, GROUPS, USERS)
                .getQuotasSection(OVERALL)
                .addQuota()
                .ensure(TITLE, text("Create storages quota"))
                .setValue(QUOTA, quota[7])
                .selectValue(PERIOD, PER_YEAR.period)
                .ensureActionsList(NOTIFY, READ_ONLY_MODE, BLOCK)
                .setAction(threshold[7], NOTIFY)
                .addRecipient(admin.login)
                .ok()
                .sleep(BILLING_QUOTAS_PERIOD, SECONDS)
                .refresh()
                .getQuotaEntry("", quotaEntry(quota[7], PER_YEAR))
                .checkQuotaStatus(YELLOW)
                .checkEntryActions(format("%s%%: %s", threshold[7], NOTIFY.toLowerCase()))
                .checkQuotaWarning()
                .removeQuota();
    }

    @Test
    @TestCase(value = {"762_7"})
    public void checkBillingCenterStoragesQuota() {
        String message = format("Billing center %s: storages quarterly expenses quota %s$. Actions: %s%% Block",
                billingCenter1, quota[8], threshold[8]);
        billingMenu()
                .click(STORAGES)
                .getQuotasSection(BILLING_CENTERS)
                .removeQuotaWithPeriodIfExist(billingCenter1, PER_QUARTER)
                .addQuota()
                .ensureVisible(QUOTA, ACTIONS, THRESHOLD, BILLING_CENTER)
                .ensure(PERIOD, text(PER_MONTH.period))
                .ensureNotVisible(RECIPIENTS)
                .ensureDisable(SAVE)
                .addQuotaObject(BILLING_CENTER, billingCenter1)
                .setValue(QUOTA, quota[8])
                .selectValue(PERIOD, PER_QUARTER.period)
                .ensureActionsList(NOTIFY, READ_ONLY_MODE, BLOCK)
                .setAction(threshold[8], BLOCK)
                .ok()
                .getQuotaEntry(billingCenter1, quotaEntry(quota[8], PER_QUARTER))
                .checkEntryActions(format("%s%%: %s", threshold[8], BLOCK.toLowerCase()))
                .sleep(BILLING_QUOTAS_PERIOD, SECONDS)
                .refresh()
                .checkQuotaStatus(RED)
                .checkQuotaWarning();
        checkQuotasExceededWarningForUser(user, message);
        logout();
        loginAs(user);
        validateWhileErrorPageMessage();
        loginAs(admin);
        billingMenu()
                .click(STORAGES)
                .getQuotasSection(BILLING_CENTERS)
                .getQuotaEntry(billingCenter1, quotaEntry(quota[8], PER_QUARTER))
                .removeQuota();
        logout();
        loginAs(user)
                .settings()
                .switchToMyProfile()
                .validateUserName(user.login);
        logout();
        loginAs(admin);
    }

    @Test
    @TestCase(value = {"762_8"})
    public void checkGroupsStoragesBillingQuotaForUserGroup() {
        String command1 = format("echo test file >> /cloud-data/%s/test_file1.txt", testStorage1);
        String command2 = format("pipe storage cp cp://%s/file1.txt cp://%s/file1.txt", testStorage1, testStorage2);
        String command3 = format("echo test file >> /cloud-data/%s/%s/test_file1.txt", nfsPrefix, testFsStorage);
        billingMenu()
                .click(STORAGES)
                .getQuotasSection(GROUPS)
                .removeQuotaWithPeriodIfExist(USER_GROUP, PER_QUARTER)
                .addQuota()
                .ensureVisible(QUOTA, ACTIONS, THRESHOLD, GROUP)
                .ensureNotVisible(RECIPIENTS)
                .ensureDisable(SAVE)
                .addQuotaObject(GROUP, USER_GROUP)
                .setValue(QUOTA, quota[9])
                .selectValue(PERIOD, PER_QUARTER.period)
                .ensureActionsList(NOTIFY, READ_ONLY_MODE, BLOCK)
                .setAction(threshold[9], READ_ONLY_MODE)
                .ok()
                .sleep(BILLING_QUOTAS_PERIOD, SECONDS)
                .refresh()
                .getQuotaEntry(USER_GROUP, quotaEntry(quota[9], PER_QUARTER))
                .checkEntryActions(format("%s%%: %s", threshold[9], READ_ONLY_MODE.toLowerCase()))
                .checkQuotaStatus(YELLOW)
                .checkQuotaWarning();
        library()
                .selectStorage(testStorage1)
                .createFileWithContent("file1.txt", "test content");
        library()
                .selectStorage(testFsStorage)
                .createFileWithContent("file2.txt", "test content");
        logout();
        loginAs(user);
        library()
                .selectStorage(testStorage1)
                .ensureNotVisible(CREATE, UPLOAD);
        tools()
                .perform(registry, group, tool, tool -> tool.run(this))
                .log(getLastRunId(), log -> log.waitForSshLink()
                        .inAnotherTab(logTab ->
                                Stream.of(command1, command2, command3).forEach(command -> {
                                    logTab.ssh(shell -> shell
                                            .waitUntilTextAppears(getLastRunId())
                                            .execute(command)
                                            .waitUntilTextAppearsSeveralTimes(getLastRunId(), 2)
                                            .assertOutputContains("Read-only file system")
                                            .sleep(2, SECONDS));
                                })
                        ));
    }


    @Test
    @TestCase(value = {"762_10"})
    public void checkUsersStoragesQuota() {
        String message = format("User %s: storages annual expenses quota %s$. Actions: %s%% Block",
                userWithoutCompletedRuns.login, quota[11], threshold[11]);
        billingMenu()
                .click(STORAGES)
                .getQuotasSection(USERS)
                .removeQuotaWithPeriodIfExist(userWithoutCompletedRuns.login, PER_YEAR)
                .removeQuotaWithPeriodIfExist(admin.login, PER_YEAR)
                .addQuota()
                .ensureVisible(QUOTA, ACTIONS, THRESHOLD, USER_NAME)
                .ensure(PERIOD, text(PER_MONTH.period))
                .ensureDisable(SAVE)
                .addQuotaObject(USER_NAME, userWithoutCompletedRuns.login)
                .setValue(QUOTA, quota[11])
                .selectValue(PERIOD, PER_YEAR.period)
                .setAction(threshold[11], BLOCK)
                .ok()
                .addQuota()
                .addQuotaObject(USER_NAME, admin.login)
                .setValue(QUOTA, quota[12])
                .selectValue(PERIOD, PER_YEAR.period)
                .setAction(threshold[12], BLOCK)
                .ok()
                .getQuotaEntry(billingCenter1, quotaEntry(quota[11], PER_YEAR))
                .checkEntryActions(format("%s%%: %s", threshold[11], BLOCK.toLowerCase()))
                .sleep(BILLING_QUOTAS_PERIOD, SECONDS)
                .refresh()
                .checkQuotaStatus(RED)
                .checkQuotaWarning();
        checkQuotasExceededWarningForUser(userWithoutCompletedRuns, message);
        logout();
        loginAs(userWithoutCompletedRuns);
        validateWhileErrorPageMessage();
        loginAs(admin);
        billingMenu()
                .click(STORAGES)
                .getQuotasSection(USERS)
                .getQuotaEntry(userWithoutCompletedRuns.login, quotaEntry(quota[11], PER_YEAR))
                .removeQuota()
                .getQuotaEntry(admin.login, quotaEntry(quota[12], PER_YEAR))
                .removeQuota();
        logout();
        loginAs(user)
                .settings()
                .switchToMyProfile()
                .validateUserName(userWithoutCompletedRuns.login);
        logout();
        loginAs(admin);
    }

    private File updateDataBillingFile() {
        final LocalDate currentDate = LocalDate.now();
        final String result = Utils.readResourceFully(format("/%s", billingData))
                .replaceAll("<user_name1>", admin.login)
                .replaceAll("<user_name2>", user.login)
                .replaceAll("<user_name3>", userWithoutCompletedRuns.login)
                .replaceAll("<group1>", C.ROLE_USER)
                .replaceAll("<billing_center1>", billingCenter1)
                .replaceAll("<billing_center2>", billingCenter2)
                .replaceAll("<start_data1>", currentDate.format(ofPattern("yyyy-MM-01")))
                .replaceAll("<start_data2>", currentDate.format(ofPattern("yyyy-01-01")))
                .replaceAll("<end_data>", currentDate.format(ofPattern(DATE_PATTERN)))
                .replaceAll("<runId1>", runId[0])
                .replaceAll("<runId2>", runId[1])
                .replaceAll("<runId3>", runId[2])
                .replaceAll("<storage1>", storageID[0])
                .replaceAll("<fsStorage>", fsStorageID)
                .replaceAll("<storage2>", storageID[1])
                .replaceAll("<billing1>", billing[0])
                .replaceAll("<billing2>", billing[1])
                .replaceAll("<billing3>", billing[2])
                .replaceAll("<billing4>", billing[3])
                .replaceAll("<billing5>", billing[4])
                .replaceAll("<billing6>", billing[5]);
        return Utils.createTempFileWithContent(billingData, result);
    }

    private String launchTool() {
        tools()
                .perform(registry, group, tool, tool -> tool.run(this));
        return getLastRunId();
    }

    private String quotaEntry(final String quota, final BillingQuotaPeriod period) {
        return format("%s$ %s",
                NumberFormat.getInstance(ENGLISH).format(Integer.valueOf(quota)),
                period.period);
    }

    public void createBillingCenter(final String dict, final String billingCenter) {
        final SystemDictionariesAO systemDictionariesAO = navigationMenu()
                .settings()
                .switchToSystemDictionaries();
        billingGroupDictionaryExist = systemDictionariesAO
                .systemDictionaryIsExist(dict);
        if (!billingGroupDictionaryExist) {
            systemDictionariesAO
                    .addNewDictionary(dict, billingCenter);
            return;
        }
        systemDictionariesAO
                .openSystemDictionary(dict)
                .addDictionaryValue(billingCenter);
    }

    public void deleteBillingCenter(final String dict, final String billingCenter) {
        final SystemDictionariesAO systemDictionariesAO = navigationMenu()
                .settings()
                .switchToSystemDictionaries();
        if (!billingGroupDictionaryExist) {
            systemDictionariesAO
                    .openSystemDictionary(dict)
                    .deleteDictionary(dict);
            return;
        }
        systemDictionariesAO
                .openSystemDictionary(dict)
                .deleteDictionaryValue(billingCenter)
                .click(SAVE);
    }

    private void checkQuotasExceededWarningForUser(Account user_name, String ... messages) {
        UsersTabAO usersTabAO = navigationMenu()
                .settings()
                .switchToUserManagement()
                .switchToUsers();
        usersTabAO
                .searchForUserEntry(user_name.login)
                .isQuotasExceeded()
                .checkQuotasExceededWarning(messages);
        usersTabAO
                .searchUserEntry(admin.login)
                .isNotQuotasExceeded();
    }
}
