/*
 * Copyright 2017-2020 EPAM Systems, Inc. (https://www.epam.com/)
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

import React from 'react';
import {BarsOutlined, CaretDownOutlined, CaretUpOutlined} from '@ant-design/icons';
import {observer} from 'mobx-react';
import {colors} from './colors';
import Export from '../export';
import {costTickFormatter, dateRangeRenderer} from '../utilities';
import {discounts} from '../discounts';
import styles from './billing-table.css';

function LegendItem ({color}) {
  return (
    <div
      className={styles.legend}
      style={{backgroundColor: color}}
    >
      {'\u00A0'}
    </div>
  );
}

function BillingTable (
  {
    compute,
    storages,
    computeDiscounts,
    storagesDiscounts,
    showQuota = true
  }
) {
  const summary = discounts.joinSummaryDiscounts(
    [compute, storages],
    [computeDiscounts, storagesDiscounts]
  );
  const data = summary || {};
  const [filters = {}] = [compute, storages].filter(Boolean).map(a => a.filters);
  const {
    start,
    endStrict: end,
    previousStart,
    previousEndStrict: previousEnd
  } = filters;
  let currentInfo, previousInfo;
  const {quota, previousQuota, values} = data || {};
  const renderQuotaColumn = showQuota && (quota || previousQuota);
  const lastValue = (values || [])
    .filter(v => v.value && v.initialDate <= end)
    .pop();
  const lastPreviousValue = (values || [])
    .filter(v => v.previous && v.initialDate <= previousEnd)
    .pop();
  currentInfo = {
    quota,
    value: lastValue ? lastValue.value : false,
    dates: {
      from: start,
      to: end
    }
  };
  previousInfo = {
    quota: previousQuota,
    value: lastPreviousValue ? lastPreviousValue.previous : false,
    dates: {
      from: previousStart,
      to: previousEnd
    }
  };
  const quotaOverrun = quota && currentInfo?.value > quota;

  const renderValue = (value) => {
    if (!isNaN(value) && value) {
      return costTickFormatter(value);
    }
    return '-';
  };
  const renderDates = ({from, to} = {}) => dateRangeRenderer(from, to) || '-';
  const renderWarning = (currentInfo = {}, previousInfo = {}) => {
    const {value: current} = currentInfo;
    const {value: previous} = previousInfo;
    let percent = 0;
    if (current && previous && !isNaN(current) && !isNaN(previous)) {
      percent = ((current - previous) / previous * 100).toFixed(2);
    }
    const containerClassNames = [
      styles.warningContainer,
      percent > 0 ? styles.negative : false,
      percent < 0 ? styles.positive : false
    ].filter(Boolean).join(' ');
    return (
      <div className={containerClassNames}>
        {quotaOverrun && (<BarsOutlined className={styles.quotaOverrunIcon} />)}
        {percent !== 0 && (
          percent > 0
            ? <CaretUpOutlined className={styles.warningIcon} />
            : <CaretDownOutlined className={styles.warningIcon} />
        )}
        {percent !== 0 && <span>{percent > 0 ? '+' : ''}{percent}%</span>}
      </div>
    );
  };
  const renderInfo = (title, color, info, isCurrent) => {
    const dateClassNames = [
      !info ? styles.pending : false,
      styles.date
    ].filter(Boolean);
    const valueClassNames = [
      !info ? styles.pending : false,
      renderQuotaColumn && info && info.value > info.quota ? styles.bold : false,
      isCurrent ? styles.bold : false,
      styles.value
    ].filter(Boolean);
    const quotaClassNames = [
      !info ? styles.pending : false,
      styles.value
    ].filter(Boolean);
    return (
      <tr>
        <td className={styles.legendRow}>
          <LegendItem color={color} />
          <span>{title}</span>
        </td>
        <td className={dateClassNames.join(' ')}>
          <span>{renderDates(info ? info.dates : undefined)}</span>
        </td>
        <td className={valueClassNames.join(' ')}>
          <span>{renderValue(info ? info.value : undefined)}</span>
        </td>
        {
          renderQuotaColumn &&
          (
            <td className={quotaClassNames.join(' ')}>
              <span>{renderValue(info ? info.quota : undefined)}</span>
            </td>
          )
        }
        <td className={[styles.quota, styles.borderless].join(' ')}>
          <span>{isCurrent && renderWarning(currentInfo, previousInfo)}</span>
        </td>
      </tr>
    );
  };
  return (
    <Export.ImageConsumer
      className={styles.container}
      order={0}
    >
      <table className={styles.table}>
        <tbody>
          {
            renderQuotaColumn && (
              <tr>
                <td className={styles.borderless} colSpan={2}>{'\u00A0'}</td>
                <td>Quota</td>
                <td className={[styles.quota, styles.borderless].join(' ')}>{'\u00A0'}</td>
              </tr>
            )
          }
          {renderInfo('Current', colors.current, currentInfo, true)}
          {renderInfo('Previous', colors.previous, previousInfo)}
        </tbody>
      </table>
    </Export.ImageConsumer>
  );
}

export default observer(BillingTable);
