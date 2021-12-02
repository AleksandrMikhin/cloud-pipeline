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
  identifier: 'dark-theme',
  name: 'Dark',
  extends: 'light-theme',
  predefined: true,
  configuration: {
    '@application-background-color': 'rgb(14, 17, 22)',
    '@application-color': 'rgb(180, 188, 196)',
    '@application-color-faded': 'fadeout(@application-color, 20%)',
    '@application-color-disabled': 'fadeout(@application-color, 60%)',
    '@application-color-accent': 'lighten(@application-color, 10%)',
    '@primary-color': '#00b1f1',
    '@primary-hover-color': 'lighten(@primary-color, 20%)',
    '@primary-active-color': '@primary-color',
    '@primary-text-color': '@application-background-color',
    '@primary-color-semi-transparent': 'fade(@primary-color, 20%)',
    '@color-success': '#118a4e',
    '@color-error': '#ed4b30',
    '@color-warning': '#f08732',
    '@color-info': '#00b1f1',
    '@color-green': '#118a4e',
    '@color-red': '#ed4b30',
    '@color-yellow': '#f08732',
    '@color-blue': '#00b1f1',
    '@color-violet': '#c730ea',
    '@color-sensitive': '#ff5c33',
    '@color-aqua': '#008080',
    '@color-aqua-light': '#7dccc0',
    '@color-pink': '#d14',
    '@color-pink-dusty': '#313030',
    '@color-pink-light': '#fef0ef',
    '@color-blue-dimmed': '#458',
    '@color-grey': '#777',
    '@spinner': '@application-color',
    '@element-hover-color': '@application-color',
    '@element-hover-background-color': 'lighten(@panel-background-color, 5%)',
    '@element-selected-color': '@application-color',
    '@element-selected-background-color': 'lighten(@panel-background-color, 10%)',
    '@input-background': '@panel-background-color',
    '@input-background-disabled': 'lighten(@input-background, 5%)',
    '@input-addon': 'lighten(@input-background, 5%)',
    '@input-border': 'lighten(@application-background-color, 15%)',
    '@input-color': '@application-color',
    '@input-placeholder-color': 'fadeout(@application-color, 40%)',
    '@input-border-hover-color': '@primary-hover-color',
    '@input-shadow-color': 'fade(@input-border-hover-color, 10%)',
    '@input-search-icon-color': 'rgba(180, 188, 196, 0.3)',
    '@input-search-icon-hovered-color': '@primary-hover-color',
    '@panel-background-color': 'rgb(23, 27, 33)',
    '@panel-border-color': 'rgb(41, 46, 54)',
    '@card-background-color': '@panel-background-color',
    '@card-border-color': '@panel-border-color',
    '@card-hovered-shadow-color': '@card-border-color',
    '@card-actions-active-background': '@card-background-color',
    '@card-header-background': '@card-border-color',
    '@card-service-background-color': 'lighten(@card-background-color, 5%)',
    '@card-service-border-color': '@card-service-background-color',
    '@card-service-hovered-shadow-color': 'transparent',
    '@card-service-actions-active-background': '@card-service-background-color',
    '@card-service-header-background': '@card-service-background-color',
    '@navigation-panel-color': '@application-background-color',
    '@navigation-panel-color-impersonated': '#943813',
    '@navigation-panel-highlighted-color': 'lighten(@navigation-panel-color, 5%)',
    '@navigation-panel-highlighted-color-impersonated': 'darken(@navigation-panel-color-impersonated, 10%)',
    '@navigation-item-color': '@application-color',
    '@navigation-item-runs-color': '@color-success',
    '@tag-key-background-color': 'lighten(@card-background-color, 5%)',
    '@tag-key-value-divider-color': '@card-background-color',
    '@tag-value-background-color': 'lighten(@card-background-color, 5%)',
    '@nfs-icon-color': '@color-success',
    '@aws-icon': "@static_resource('icons/providers/aws-light.svg')",
    '@aws-icon-contrast': "@static_resource('icons/providers/aws-light.svg')",
    '@gcp-icon': "@static_resource('icons/providers/gcp.svg')",
    '@gcp-icon-contrast': "@static_resource('icons/providers/gcp.svg')",
    '@azure-icon': "@static_resource('icons/providers/azure.svg')",
    '@azure-icon-contrast': "@static_resource('icons/providers/azure.svg')",
    '@modal-mask-background': 'rgba(0, 0, 0, 0.6)',
    '@even-element-background': 'lighten(@card-background-color, 5%)',
    '@alert-success-background': 'darken(@color-success, 15%)',
    '@alert-success-border': '@color-success',
    '@alert-success-icon': '@color-success',
    '@alert-warning-background': 'darken(@color-warning, 15%)',
    '@alert-warning-border': '@color-warning',
    '@alert-warning-icon': '@color-warning',
    '@alert-error-background': 'darken(@color-error, 15%)',
    '@alert-error-border': '@color-error',
    '@alert-error-icon': '@color-error',
    '@alert-info-background': 'darken(@color-info, 15%)',
    '@alert-info-border': '@color-info',
    '@alert-info-icon': '@color-info',
    '@table-element-selected-background-color': '@element-selected-background-color',
    '@table-element-selected-color': '@element-selected-color',
    '@table-element-hover-background-color': '@element-hover-background-color',
    '@table-element-hover-color': '@element-hover-color',
    '@table-border-color': '@card-border-color',
    '@table-head-color': '@application-color-accent',
    '@menu-color': '@application-color',
    '@menu-active-color': '@application-color',
    '@menu-border-color': '@panel-border-color',
    '@btn-color': '@primary-text-color',
    '@btn-primary-active': '@primary-active-color',
    '@btn-danger-color': '@color-error',
    '@btn-danger-background-color': '@btn-disabled-background-color',
    '@btn-danger-active-color': 'darken(@btn-danger-color, 20%)',
    '@btn-disabled-color': 'lighten(@panel-background-color, 40%)',
    '@btn-disabled-background-color': 'lighten(@panel-background-color, 4%)',
    '@code-background-color': 'lighten(@card-background-color, 5%)',
    '@search-highlight-text-color': '@application-color',
    '@search-highlight-text-background-color': '@navigation-panel-color-impersonated'
  }
};
