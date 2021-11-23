package com.epam.pipeline.manager.billing;

import com.epam.pipeline.controller.vo.billing.BillingExportRequest;
import com.epam.pipeline.controller.vo.billing.BillingExportType;
import com.epam.pipeline.entity.billing.BillingGrouping;
import com.epam.pipeline.entity.billing.InstanceReportBilling;
import com.epam.pipeline.entity.billing.InstanceReportBillingMetrics;
import com.epam.pipeline.exception.search.SearchException;
import com.epam.pipeline.manager.preference.PreferenceManager;
import com.epam.pipeline.manager.utils.GlobalSearchElasticHelper;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.search.aggregations.Aggregations;
import org.elasticsearch.search.aggregations.bucket.histogram.DateHistogramAggregationBuilder;
import org.elasticsearch.search.aggregations.bucket.histogram.ParsedDateHistogram;
import org.elasticsearch.search.aggregations.bucket.terms.ParsedStringTerms;
import org.elasticsearch.search.aggregations.bucket.terms.ParsedTerms;
import org.elasticsearch.search.aggregations.pipeline.PipelineAggregatorBuilders;
import org.elasticsearch.search.aggregations.pipeline.bucketmetrics.sum.SumBucketPipelineAggregationBuilder;
import org.elasticsearch.search.aggregations.pipeline.bucketsort.BucketSortPipelineAggregationBuilder;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.sort.FieldSortBuilder;
import org.elasticsearch.search.sort.SortOrder;
import org.springframework.stereotype.Service;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Service
@RequiredArgsConstructor
public class InstanceReportExporter implements BillingExporter {

    @Getter
    private final BillingExportType type = BillingExportType.INSTANCE_REPORT;
    private final BillingHelper billingHelper;
    private final GlobalSearchElasticHelper elasticHelper;
    private final PreferenceManager preferenceManager;

    @Override
    public void export(final BillingExportRequest request, final OutputStream out) {
        try (OutputStreamWriter outputStreamWriter = new OutputStreamWriter(out);
             BufferedWriter bufferedWriter = new BufferedWriter(outputStreamWriter);
             InstanceReportWriter writer = new InstanceReportWriter(bufferedWriter, billingHelper,
                     preferenceManager, request.getFrom(), request.getTo());
             RestHighLevelClient elasticSearchClient = elasticHelper.buildClient()) {
            writer.writeHeader();
            billings(request, elasticSearchClient).forEach(writer::write);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            throw new SearchException(e.getMessage(), e);
        }
    }

    private Stream<InstanceReportBilling> billings(final BillingExportRequest request,
                                                   final RestHighLevelClient elasticSearchClient) {
        final LocalDate from = request.getFrom();
        final LocalDate to = request.getTo();
        final Map<String, List<String>> filters = billingHelper.getFilters(request.getFilters());
        return billings(elasticSearchClient, from, to, filters);
    }

    private Stream<InstanceReportBilling> billings(final RestHighLevelClient elasticSearchClient,
                                                   final LocalDate from,
                                                   final LocalDate to,
                                                   final Map<String, List<String>> filters) {
        return Optional.of(getRequest(from, to, filters))
                .map(billingHelper.searchWith(elasticSearchClient))
                .map(this::billings)
                .orElseGet(Stream::empty);
    }

    private Stream<InstanceReportBilling> billings(final SearchResponse response) {
        return Optional.ofNullable(response.getAggregations())
                .map(it -> it.get(BillingGrouping.RUN_INSTANCE_TYPE.getCorrespondingField()))
                .filter(ParsedStringTerms.class::isInstance)
                .map(ParsedStringTerms.class::cast)
                .map(ParsedTerms::getBuckets)
                .map(Collection::stream)
                .orElse(Stream.empty())
                .map(bucket -> getBilling(bucket.getKeyAsString(), bucket.getAggregations()));
    }

    private InstanceReportBilling getBilling(final String name, final Aggregations aggregations) {
        return InstanceReportBilling.builder()
                .name(name)
                .totalMetrics(InstanceReportBillingMetrics.builder()
                        .runsNumber(billingHelper.getRunCount(aggregations).orElse(NumberUtils.LONG_ZERO))
                        .runsDuration(billingHelper.getRunUsageSum(aggregations).orElse(NumberUtils.LONG_ZERO))
                        .runsCost(billingHelper.getCostSum(aggregations).orElse(NumberUtils.LONG_ZERO))
                        .build())
                .periodMetrics(getPeriodMetrics(aggregations))
                .build();
    }

    private Map<YearMonth, InstanceReportBillingMetrics> getPeriodMetrics(final Aggregations aggregations) {
        return Optional.ofNullable(aggregations)
                .map(it -> it.get(BillingHelper.HISTOGRAM_AGGREGATION_NAME))
                .filter(ParsedDateHistogram.class::isInstance)
                .map(ParsedDateHistogram.class::cast)
                .map(ParsedDateHistogram::getBuckets)
                .map(Collection::stream)
                .orElseGet(Stream::empty)
                .map(bucket -> getPeriodMetrics(bucket.getKeyAsString(), bucket.getAggregations()))
                .collect(Collectors.toMap(Pair::getLeft, Pair::getRight));
    }

    private Pair<YearMonth, InstanceReportBillingMetrics> getPeriodMetrics(final String ym,
                                                                           final Aggregations aggregations) {
        return Pair.of(YearMonth.parse(ym, DateTimeFormatter.ofPattern(BillingHelper.HISTOGRAM_AGGREGATION_FORMAT)),
                InstanceReportBillingMetrics.builder()
                        .runsNumber(billingHelper.getRunCount(aggregations).orElse(NumberUtils.LONG_ZERO))
                        .runsDuration(billingHelper.getRunUsageSum(aggregations).orElse(NumberUtils.LONG_ZERO))
                        .runsCost(billingHelper.getCostSum(aggregations).orElse(NumberUtils.LONG_ZERO))
                        .build());
    }

    private SearchRequest getRequest(final LocalDate from,
                                     final LocalDate to,
                                     final Map<String, List<String>> filters) {
        return new SearchRequest()
                .indicesOptions(IndicesOptions.strictExpandOpen())
                .indices(billingHelper.runIndicesByDate(from, to))
                .source(new SearchSourceBuilder()
                        .size(0)
                        .query(billingHelper.queryByDateAndFilters(from, to, filters))
                        .aggregation(billingHelper.aggregateBy(BillingGrouping.RUN_INSTANCE_TYPE.getCorrespondingField())
                                .size(Integer.MAX_VALUE)
                                .subAggregation(aggregateBillingsByMonth())
                                .subAggregation(aggregateRunCountSumBucket())
                                .subAggregation(aggregateRunUsageSumBucket())
                                .subAggregation(aggregateCostSumBucket())
                                .subAggregation(aggregateCostSortBucket())));
    }

    private DateHistogramAggregationBuilder aggregateBillingsByMonth() {
        return billingHelper.aggregateByMonth()
                .subAggregation(billingHelper.aggregateUniqueRunsCount())
                .subAggregation(billingHelper.aggregateRunUsageSum())
                .subAggregation(billingHelper.aggregateCostSum());
    }

    private SumBucketPipelineAggregationBuilder aggregateCostSumBucket() {
        return PipelineAggregatorBuilders
                .sumBucket(BillingHelper.COST_FIELD,
                        String.join(BillingHelper.ES_DOC_AGGS_SEPARATOR, BillingHelper.HISTOGRAM_AGGREGATION_NAME, BillingHelper.COST_FIELD));
    }

    private BucketSortPipelineAggregationBuilder aggregateCostSortBucket() {
        return PipelineAggregatorBuilders.bucketSort(BillingHelper.SORT_AGG,
                Collections.singletonList(new FieldSortBuilder(BillingHelper.COST_FIELD)
                        .order(SortOrder.DESC)));
    }

    private SumBucketPipelineAggregationBuilder aggregateRunUsageSumBucket() {
        return PipelineAggregatorBuilders
                .sumBucket(BillingHelper.RUN_USAGE_AGG,
                        String.join(BillingHelper.ES_DOC_AGGS_SEPARATOR, BillingHelper.HISTOGRAM_AGGREGATION_NAME, BillingHelper.RUN_USAGE_AGG));
    }

    private SumBucketPipelineAggregationBuilder aggregateRunCountSumBucket() {
        return PipelineAggregatorBuilders
                .sumBucket(BillingHelper.RUN_COUNT_AGG,
                        String.join(BillingHelper.ES_DOC_AGGS_SEPARATOR, BillingHelper.HISTOGRAM_AGGREGATION_NAME, BillingHelper.RUN_COUNT_AGG));
    }
}
