package com.novawaf.admin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

@Configuration
public class ThreadPoolConfig {
    /** 业务线程池: 审计日志等慢 IO 异步化, 不阻塞请求线程 */
    @Bean("bizExecutor")
    public Executor bizExecutor() {
        int cpu = Runtime.getRuntime().availableProcessors();
        ThreadPoolTaskExecutor ex = new ThreadPoolTaskExecutor();
        ex.setCorePoolSize(cpu);
        ex.setMaxPoolSize(cpu * 2);
        ex.setQueueCapacity(2000);
        ex.setThreadNamePrefix("biz-");
        ex.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        ex.setWaitForTasksToCompleteOnShutdown(true);
        ex.setAwaitTerminationSeconds(10);
        ex.initialize();
        return ex;
    }
}
