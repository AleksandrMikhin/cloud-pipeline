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

import {fade} from '../../../../../../themes/utilities/color-utilities';

const colors = [
  '#1890ff',
  '#faad14',
  '#a0d911',
  '#13c2c2',
  '#9254de',
  '#c41d7f',
  '#595959',
  '#ff4d4f'
];

const backgroundColor = '#ffffff';
const textColor = 'rgba(0, 0, 0, 0.65)';
const lineColor = textColor;

const FADE_AMOUNT = 0.15;

export function getColor (index, colorsConfiguration = colors) {
  const indexCorrected = Math.max(0, index) % colorsConfiguration.length;
  return colorsConfiguration[indexCorrected];
}

export function getFadedColor (color) {
  return fade(color, FADE_AMOUNT);
}

export {backgroundColor, textColor, lineColor};
export default colors;
