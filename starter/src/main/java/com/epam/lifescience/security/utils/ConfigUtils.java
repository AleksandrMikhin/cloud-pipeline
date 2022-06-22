package com.epam.lifescience.security.utils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@SuppressWarnings("checkstyle:HideUtilityClassConstructor")
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ConfigUtils {
    public static final String SLASH = "/";
    public static final String ANY_URL_PATTERN = "/**";

    public static String getUrlWithoutTrailingSlash(final String url) {
        assertUrlNotNull(url);
        return url.endsWith(SLASH) ? url.substring(0, url.length() - 1) : url;
    }

    public static String getUrlWithTrailingSlash(final String url) {
        assertUrlNotNull(url);
        return url.endsWith(SLASH) ? url : url + SLASH;
    }

    public static RequestMatcher getRequestMatcher(final String... urls) {
        Assert.notNull(urls, "Urls cannot be null");
        final List<RequestMatcher> matchers = Arrays.stream(urls)
                .filter(StringUtils::isNotBlank)
                .map(AntPathRequestMatcher::new)
                .collect(Collectors.toList());
        if (matchers.isEmpty()) {
            throw new IllegalArgumentException("Urls cannot be null and must contain at least one value");
        }
        return new OrRequestMatcher(matchers);
    }

    public static boolean isNotBlankStringArray(final String... strings) {
        if (ArrayUtils.isNotEmpty(strings)) {
            return Arrays.stream(strings).anyMatch(StringUtils::isNotBlank);
        }
        return false;
    }

    private static void assertUrlNotNull(final String url) {
        Assert.notNull(url, "Url cannot be null");
    }
}
