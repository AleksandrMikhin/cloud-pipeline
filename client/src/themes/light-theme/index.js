/*
 * Copyright 2017-2021 EPAM Systems, Inc. (https://www.epam.com/)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/* eslint-disable max-len */

export default {
  identifier: 'light-theme',
  name: 'Light',
  extends: undefined,
  predefined: true,
  configuration: {
    '@application-background-color': '#ececec',
    '@application-color': 'rgba(0, 0, 0, 0.65)',
    '@application-color-faded': 'fadeout(@application-color, 20%)',
    '@application-color-disabled': 'fadeout(@application-color, 40%)',
    '@application-color-accent': 'fadein(@application-color, 20%)',
    '@primary-color': '#108ee9',
    '@primary-hover-color': '#49a9ee',
    '@primary-active-color': '#0e77ca',
    '@primary-text-color': 'white',
    '@primary-color-semi-transparent': 'fade(@primary-color, 20%)',
    '@color-success': '#09ab5a',
    '@color-error': '#f04134',
    '@color-warning': '#ff8818',
    '@color-info': '@primary-color',
    '@color-green': 'rgb(9, 171, 90)',
    '@color-green-semi-transparent': 'fadeout(@color-green, 90%)',
    '@color-red': 'rgb(240, 65, 52)',
    '@color-red-semi-transparent': 'fadeout(@color-red, 90%)',
    '@color-yellow': 'rgb(255, 136, 24)',
    '@color-blue': '@primary-color',
    '@color-violet': '#8d09ab',
    '@color-sensitive': '#ff5c33',
    '@color-aqua': '#008080',
    '@color-aqua-light': '#7dccc0',
    '@color-pink': '#d14',
    '@color-pink-dusty': '#f0efef',
    '@color-pink-light': '#fef0ef',
    '@color-blue-dimmed': '#458',
    '@color-grey': '#777',
    '@spinner': '@primary-color',
    '@element-hover-color': '@application-color',
    '@element-hover-background-color': '#ecf6fd',
    '@element-selected-color': '@application-color',
    '@element-selected-background-color': '#f7f7f7',
    '@input-background': '#fff',
    '@input-background-disabled': '#f7f7f7',
    '@input-addon': '#eee',
    '@input-border': '#d9d9d9',
    '@input-color': 'rgba(0, 0, 0, 0.65)',
    '@input-placeholder-color': 'rgba(0, 0, 0, 0.3)',
    '@input-border-hover-color': '@primary-hover-color',
    '@input-shadow-color': 'fade(@input-border-hover-color, 20%)',
    '@input-search-icon-color': 'rgba(0, 0, 0, 0.65)',
    '@input-search-icon-hovered-color': '@primary-hover-color',
    '@panel-background-color': 'white',
    '@panel-border-color': '#ccc',
    '@card-background-color': 'white',
    '@card-border-color': '#ddd',
    '@card-hovered-shadow-color': 'rgba(0, 0, 0, 0.2)',
    '@card-actions-active-background': 'fade(@primary-color, 20%)',
    '@card-header-background': '#eee',
    '@card-service-background-color': '#ffffe0',
    '@card-service-border-color': '@card-border-color',
    '@card-service-hovered-shadow-color': '@card-hovered-shadow-color',
    '@card-service-actions-active-background': '@card-actions-active-background',
    '@card-service-header-background': '@card-header-background',
    '@navigation-panel-color': '#2796dd',
    '@navigation-panel-color-impersonated': '#dd5b27',
    '@navigation-panel-highlighted-color': 'darken(@navigation-panel-color, 10%)',
    '@navigation-panel-highlighted-color-impersonated': 'darken(@navigation-panel-color-impersonated, 10%)',
    '@navigation-item-color': 'white',
    '@navigation-item-runs-color': '#0cff87',
    '@tag-key-background-color': '#efefef',
    '@tag-key-value-divider-color': '#ddd',
    '@tag-value-background-color': '#fefefe',
    '@nfs-icon-color': '#116118',
    '@public-root': "'/'",
    '@aws-icon': "@static_resource('icons/providers/aws.svg')",
    '@aws-icon-contrast': "@static_resource('icons/providers/aws-light.svg')",
    '@gcp-icon': "@static_resource('icons/providers/gcp.svg')",
    '@gcp-icon-contrast': "@static_resource('icons/providers/gcp-light.svg')",
    '@azure-icon': "@static_resource('icons/providers/azure.svg')",
    '@azure-icon-contrast': "@static_resource('icons/providers/azure.svg')",
    '@eu-region-icon': "@static_resource('icons/regions/eu.svg')",
    '@us-region-icon': "@static_resource('icons/regions/us.svg')",
    '@sa-region-icon': "@static_resource('icons/regions/sa.svg')",
    '@cn-region-icon': "@static_resource('icons/regions/cn.svg')",
    '@ca-region-icon': "@static_resource('icons/regions/ca.svg')",
    '@ap-northeast-1-region-icon': "@static_resource('icons/regions/ap-northeast-1.svg')",
    '@ap-northeast-2-region-icon': "@static_resource('icons/regions/ap-northeast-2.svg')",
    '@ap-northeast-3-region-icon': "@static_resource('icons/regions/ap-northeast-3.svg')",
    '@ap-south-1-region-icon': "@static_resource('icons/regions/ap-south-1.svg')",
    '@ap-southeast-1-region-icon': "@static_resource('icons/regions/ap-southeast-1.svg')",
    '@ap-southeast-2-region-icon': "@static_resource('icons/regions/ap-southeast-2.svg')",
    '@taiwan-region-icon': "@static_resource('icons/regions/taiwan.svg')",
    '@theme-transition-duration': '250ms',
    '@theme-transition-function': 'linear',
    '@modal-mask-background': 'rgba(55, 55, 55, 0.6)',
    '@even-element-background': 'darken(@card-background-color, 5%)',
    '@alert-success-background': '#ebf8f2',
    '@alert-success-border': '#cfefdf',
    '@alert-success-icon': '#00a854',
    '@alert-warning-background': '#fffaeb',
    '@alert-warning-border': '#fff3cf',
    '@alert-warning-icon': '#ffbf00',
    '@alert-error-background': '#fef0ef',
    '@alert-error-border': '#fcdbd9',
    '@alert-error-icon': '#f04134',
    '@alert-info-background': '#ecf6fd',
    '@alert-info-border': '#d2eafb',
    '@alert-info-icon': '@primary-color',
    '@table-element-selected-background-color': '#d2eafb',
    '@table-element-selected-color': '@element-selected-color',
    '@table-element-hover-background-color': '@element-hover-background-color',
    '@table-element-hover-color': '@element-hover-color',
    '@table-border-color': '@card-border-color',
    '@table-head-color': '@application-color-accent',
    '@deleted-row-accent': 'fadeout(@color-error, 90%)',
    '@menu-active-color': '@primary-color',
    '@btn-danger-color': '@color-error',
    '@btn-danger-background-color': '@btn-disabled-background-color',
    '@btn-danger-active-color': '@primary-text-color',
    '@btn-danger-active-background': '#d73435',
    '@btn-disabled-color': 'rgba(0, 0, 0, 0.25)',
    '@btn-disabled-background-color': '#f7f7f7',
    '@code-background-color': 'darken(@card-background-color, 5%)',
    '@card-background-color-not-faded': 'fade(@card-background-color, 100%)',
    '@search-highlight-text-color': '@application-color',
    '@search-highlight-text-background-color': 'yellow',
    '@background-image': 'none',
    '@navigation-background-image': 'none',
    '@logo-image': "@static_resource('logo.png')"
  }
};
