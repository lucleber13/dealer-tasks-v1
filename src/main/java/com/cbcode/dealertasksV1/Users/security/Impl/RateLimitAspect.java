package com.cbcode.dealertasksV1.Users.security.Impl;

import com.cbcode.dealertasksV1.ExceptionsConfig.RateLimitExceededException;
import com.cbcode.dealertasksV1.Users.security.RateLimit;
import com.google.common.util.concurrent.RateLimiter;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Aspect
@Component
public class RateLimitAspect {

    private final Map<String, RateLimiter> rateLimiters = new ConcurrentHashMap<>();

    @Around("@annotation(rateLimit)")
    public Object enforceRateLimit(@NotNull ProceedingJoinPoint joinPoint, RateLimit rateLimit) throws Throwable {
        String key = joinPoint.getSignature().toShortString();
        RateLimiter limiter = rateLimiters.computeIfAbsent(key, k -> RateLimiter.create(rateLimit.limit() / (double) rateLimit.period()));
        if (limiter.tryAcquire()) {
            return joinPoint.proceed();
        } else {
            throw new RateLimitExceededException("Too many requests");
        }
    }
}
