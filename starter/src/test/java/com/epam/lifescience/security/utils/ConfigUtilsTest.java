package com.epam.lifescience.security.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ConfigUtilsTest {
    private static final String SLASH = "/";
    private static final String SOME_URL = "www.some-url.com";
    private static final String SOME_URL_WITH_TRAILING_SLASH = SOME_URL + SLASH;
    private static final String EMPTY_URL = "";
    private static final String SOME_BLANK_URL = "\t \n";

    @ParameterizedTest
    @MethodSource("provideCorrectUrlsForGettingUrlWithoutTrailingSlash")
    void shouldReturnCorrectUrlWithoutTrailingSlash(final String url, final String expectedUrl) {
        assertEquals(expectedUrl, ConfigUtils.getUrlWithoutTrailingSlash(url));
    }

    static Stream<Arguments> provideCorrectUrlsForGettingUrlWithoutTrailingSlash() {
        return Stream.of(
                Arguments.of(EMPTY_URL, EMPTY_URL),
                Arguments.of(SLASH, EMPTY_URL),
                Arguments.of(SOME_URL_WITH_TRAILING_SLASH, SOME_URL)
        );
    }

    @ParameterizedTest
    @MethodSource("provideCorrectUrlsForGettingUrlWithTrailingSlash")
    void shouldReturnCorrectUrlWithTrailingSlash(final String url, final String expectedUrl) {
        assertEquals(expectedUrl, ConfigUtils.getUrlWithTrailingSlash(url));
    }

    static Stream<Arguments> provideCorrectUrlsForGettingUrlWithTrailingSlash() {
        return Stream.of(
                Arguments.of(EMPTY_URL, SLASH),
                Arguments.of(SOME_URL, SOME_URL_WITH_TRAILING_SLASH)
        );
    }

    @Test
    void shouldThrowIfUrlIsNull() {
        Assertions.assertAll(
            () -> assertThrows(IllegalArgumentException.class, () -> ConfigUtils.getUrlWithoutTrailingSlash(null)),
            () -> assertThrows(IllegalArgumentException.class, () -> ConfigUtils.getUrlWithTrailingSlash(null))
        );
    }

    @ParameterizedTest
    @NullAndEmptySource
    @MethodSource("provideBlankUrlArrayCases")
    void shouldThrowIfWrongUrlsWhenGettingRequestMatcher(final String... urls) {
        assertThrows(IllegalArgumentException.class, () -> ConfigUtils.getRequestMatcher(urls));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @MethodSource("provideBlankUrlArrayCases")
    void shouldReturnFalseWhenInvokeIsNotBlankStringArray(final String... strings) {
        Assertions.assertFalse(ConfigUtils.isNotBlankStringArray(strings));
    }

    static Stream<Arguments> provideBlankUrlArrayCases() {
        return Stream.<Object>of(
                        new String[]{EMPTY_URL},
                        new String[]{SOME_BLANK_URL},
                        new String[]{null, EMPTY_URL, SOME_BLANK_URL})
                .map(Arguments::of);
    }

    @Test
    void shouldReturnTrueWhenInvokeIsNotBlankStringArray() {
        Assertions.assertTrue(ConfigUtils.isNotBlankStringArray(SOME_URL));
    }
}
