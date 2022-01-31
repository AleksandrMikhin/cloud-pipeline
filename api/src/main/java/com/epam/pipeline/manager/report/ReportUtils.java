/*
 * Copyright 2017-2022 EPAM Systems, Inc. (https://www.epam.com/)
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

package com.epam.pipeline.manager.report;

import org.apache.commons.math3.stat.descriptive.rank.Median;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.function.Function;
import java.util.function.ToIntFunction;

public interface ReportUtils {

    static List<LocalDateTime> buildTimeIntervals(final LocalDateTime from, final LocalDateTime to,
                                                  final ChronoUnit intervalStep) {
        LocalDateTime intervalTime = from;
        final List<LocalDateTime> timeIntervals = new ArrayList<>();
        while (intervalTime.isBefore(to)) {
            timeIntervals.add(intervalTime);
            intervalTime = intervalTime.plus(1, intervalStep);
        }
        return timeIntervals;
    }

    static boolean dateInInterval(final LocalDateTime targetDate, final LocalDateTime intervalStart,
                                  final LocalDateTime intervalEnd) {
        return targetDate.isBefore(intervalEnd) && !targetDate.isBefore(intervalStart);
    }

    static <T> Integer calculateSampleMedian(final Function<T, Integer> getValueFunction,
                                             final List<T> records) {
        final double[] sample = records.stream()
                .map(getValueFunction)
                .filter(Objects::nonNull)
                .mapToDouble(Integer::doubleValue)
                .toArray();
        return (int) Math.round(new Median().evaluate(sample));
    }

    static <T> Integer calculateSampleMax(final ToIntFunction<T> getValueFunction,
                                          final List<T> records) {
        final OptionalInt maxValue = records.stream().mapToInt(getValueFunction).max();
        return maxValue.isPresent() ? maxValue.getAsInt() : null;
    }
}
