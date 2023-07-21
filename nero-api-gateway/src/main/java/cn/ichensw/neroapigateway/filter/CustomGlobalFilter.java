package cn.ichensw.neroapigateway.filter;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.URLUtil;
import cn.ichensw.neroapicommon.common.ErrorCode;
import cn.ichensw.neroapicommon.model.entity.InterfaceInfo;
import cn.ichensw.neroapicommon.model.entity.User;
import cn.ichensw.neroapicommon.model.entity.UserInterfaceInfo;
import cn.ichensw.neroapicommon.service.InnerInterfaceInfoService;
import cn.ichensw.neroapicommon.service.InnerUserInterfaceInfoService;
import cn.ichensw.neroapicommon.service.InnerUserService;
import cn.ichensw.neroapigateway.exception.BusinessException;
import cn.ichensw.neroclientsdk.utils.SignUtils;
import jodd.util.StringUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.annotation.Resource;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * 自定义全局过滤器
 *
 * @author 嘻精
 * @date 2023/07/21
 */
@Component
@Slf4j
@Data
public class CustomGlobalFilter implements GlobalFilter, Ordered {

    public static final List<String> IP_WHITE_LIST = Collections.singletonList("127.0.0.1");
    private static final String DYE_DATA_HEADER = "X-Dye-Data";
    private static final String DYE_DATA_VALUE = "nero";

    @DubboReference
    private InnerUserService innerUserService;
    @DubboReference
    private InnerUserInterfaceInfoService innerUserInterfaceInfoService;
    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;
    @Resource
    private RedissonClient redissonClient;
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 1. 请求日志
        ServerHttpRequest request = exchange.getRequest();
        String IP_ADDRESS = Objects.requireNonNull(request.getLocalAddress()).getHostString();
        String path = request.getPath().value();
        log.info("请求唯一标识：{}", request.getId());
        log.info("请求路径：{}", path);
        log.info("请求参数：{}", request.getQueryParams());
        log.info("请求来源地址：{}", IP_ADDRESS);
        log.info("请求来源地址：{}", request.getRemoteAddress());

        ServerHttpResponse response = exchange.getResponse();

        // 2. 黑白名单
        if (!IP_WHITE_LIST.contains(IP_ADDRESS)) {
            return handleNoAuth(response);
        }
        // 3. 用户鉴权 （判断 accessKey 和 secretKey 是否合法）
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String timestamp = headers.getFirst("timestamp");
        String nonce = headers.getFirst("nonce");
        String sign = headers.getFirst("sign");
        String body = URLUtil.decode(headers.getFirst("body"), CharsetUtil.CHARSET_UTF_8);
        String method = headers.getFirst("method");

        if (StringUtil.isEmpty(nonce)
                || StringUtil.isEmpty(sign)
                || StringUtil.isEmpty(timestamp)
                || StringUtil.isEmpty(method)) {
            throw new BusinessException(ErrorCode.FORBIDDEN_ERROR, "请求头参数不完整！");
        }

        // 通过 accessKey 查询是否存在该用户
        User invokeUser = innerUserService.getInvokeUser(accessKey);
        if (invokeUser == null) {
            throw new BusinessException(ErrorCode.FORBIDDEN_ERROR, "accessKey 不合法！");
        }
        // 判断随机数是否存在，防止重放攻击
        String existNonce = (String) redisTemplate.opsForValue().get(nonce);
        if (StringUtil.isNotBlank(existNonce)) {
            throw new BusinessException(ErrorCode.FORBIDDEN_ERROR, "请求重复！");
        }
        // 时间戳 和 当前时间不能超过 5 分钟 (300000毫秒)
        long currentTimeMillis = System.currentTimeMillis() / 1000;
        long difference = currentTimeMillis - Long.parseLong(timestamp);
        if (Math.abs(difference) > 300000) {
            throw new BusinessException(ErrorCode.FORBIDDEN_ERROR, "请求超时！");
        }
        // 校验签名
        // 应该通过 accessKey 查询数据库中的 secretKey 生成 sign 和前端传递的 sign 对比
        String serverSign = SignUtils.genSign(body, invokeUser.getSecretKey());
        if (!sign.equals(serverSign)) {
            throw new BusinessException(ErrorCode.FORBIDDEN_ERROR, "签名错误！");
        }

        // 4. 请求的模拟接口是否存在？
        // 从数据库中查询接口是否存在，以及方法是否匹配（还有请求参数是否正确）
        InterfaceInfo interfaceInfo = null;
        try {
            interfaceInfo = innerInterfaceInfoService.getInterfaceInfo(path, method);
        } catch (Exception e) {
            log.error("getInvokeInterface error", e);
        }
        if (interfaceInfo == null) {
            throw new BusinessException(ErrorCode.SYSTEM_ERROR, "接口不存在！");
        }

        // 5. 请求转发，调用模拟接口
        // 6. 响应日志
        return handleResponse(exchange, chain, interfaceInfo.getId(), invokeUser.getId());
    }

    @Override
    public int getOrder() {
        return -1;
    }

    /**
     * 响应没权限
     *
     * @param response
     * @return
     */
    private Mono<Void> handleNoAuth(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.setRawStatusCode(HttpStatus.FORBIDDEN.value());
        return response.setComplete();
    }

    /**
     * 处理响应
     *
     * @param exchange
     * @param chain
     * @return
     */
    private Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain, long interfaceInfoId, long userId) {
        try {
            ServerHttpResponse originalResponse = exchange.getResponse();
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();

            HttpStatus statusCode = originalResponse.getStatusCode();

            if (statusCode == HttpStatus.OK) {
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            return super.writeWith(
                                    fluxBody.map(dataBuffer -> {
                                        // 7. 调用成功，接口调用次数 + 1 invokeCount
                                        try {
                                            postHandler(exchange.getRequest(), exchange.getResponse(), interfaceInfoId, userId);
                                        } catch (Exception e) {
                                            log.error("invokeCount error", e);
                                            throw new BusinessException(ErrorCode.SYSTEM_ERROR, "接口调用次数 + 1 失败！");
                                        }
                                        byte[] content = new byte[dataBuffer.readableByteCount()];
                                        dataBuffer.read(content);
                                        DataBufferUtils.release(dataBuffer);//释放掉内存
                                        // 构建日志
                                        StringBuilder sb2 = new StringBuilder(200);
                                        List<Object> rspArgs = new ArrayList<>();
                                        rspArgs.add(originalResponse.getStatusCode());
                                        String data = new String(content, StandardCharsets.UTF_8); //data
                                        sb2.append(data);
                                        // 打印日志
                                        log.info("响应结果：" + data);
                                        return bufferFactory.wrap(content);
                                    })
                            );
                        } else {
                            // 8. 调用失败，返回规范的错误码
                            log.error("<--- {} 响应code异常", getStatusCode());
                        }
                        return super.writeWith(body);
                    }
                };

                // 流量染色，只有染色数据才能被调用
                /**
                 * 接下来，对原始请求进行染色处理，即创建一个新的ServerHttpRequest对象，通过调用mutate方法对原始请求进行修改，
                 * 添加一个名为"DYE_DATA_HEADER"的请求头，值为"DYE_DATA_VALUE"。
                 * 然后，创建一个新的ServerWebExchange对象，通过调用mutate方法对原始ServerWebExchange对象进行修改，
                 * 将修改后的请求和装饰后的响应对象设置到新的ServerWebExchange中。
                 * 最后，调用chain.filter方法，将新的ServerWebExchange对象传递给下一个过滤器链进行处理。
                 * 这样，只有在流量染色的请求中，才会执行接口调用次数 + 1的逻辑，并带有染色数据的请求才会被传递给下一个过滤器链处理。
                 * 对于其他请求，会执行降级处理逻辑，返回降级后的响应数据。
                 * 流量染色的目的是对特定的请求进行标记，以便在后续的处理中进行特殊处理或者进行统计分析。
                 * 在这段代码中，流量染色的实现是通过添加请求头的方式进行的，但实际实现方式可以根据需求进行调整。
                 */
                ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                        .header(DYE_DATA_HEADER, DYE_DATA_VALUE)
                        .build();

                ServerWebExchange serverWebExchange = exchange.mutate()
                        .request(modifiedRequest)
                        .response(decoratedResponse)
                        .build();
                return chain.filter(serverWebExchange);
            }
            //降级处理返回数据
            return chain.filter(exchange);
        } catch (Exception e) {
            log.error("网关处理异常响应.\n" + e);
            return chain.filter(exchange);
        }
    }
    
    /**
     * post处理程序
     * 这段代码是一个私有方法，用于在接口调用成功时，增加接口调用次数。
     * 方法接收四个参数：`ServerHttpRequest request`，`ServerHttpResponse response`，`Long interfaceInfoId`，`Long userId`。
     * 首先，通过调用RedissonClient对象的getLock方法，获取一个名为"api:add_interface_num"的分布式锁对象lock。
     * 然后，判断响应的状态码是否为HttpStatus.OK（即200）。如果是，则创建一个CompletableFuture异步任务，并在任务中进行以下操作：
     * 1. 尝试获得分布式锁lock，如果成功获取到锁，则执行以下操作：
     * 2. 调用addInterfaceNum方法，传入请求对象、接口信息ID和用户ID，实现接口调用次数 + 1的逻辑。
     * 3. 最后，无论是否成功获取到锁，都需要释放锁。
     * 通过异步任务的方式执行接口调用次数 + 1的操作，可以减少接口调用的等待时间，提高系统的响应速度。
     * 需要注意的是，这段代码中使用了分布式锁来保证接口调用次数的准确性。
     * 分布式锁的作用是在多个系统实例之间协调共享资源的访问，确保同一时间只有一个实例能够获取到锁，从而避免资源竞争和数据不一致的问题。
     *
     * @param request         请求
     * @param response        响应
     * @param interfaceInfoId 接口信息id
     * @param userId          用户id
     */
    private void postHandler(ServerHttpRequest request, ServerHttpResponse response, Long interfaceInfoId, Long userId) {
        RLock lock = redissonClient.getLock("api:add_interface_num");
        if (response.getStatusCode() == HttpStatus.OK) {
            CompletableFuture.runAsync(() -> {
                if (lock.tryLock()) {
                    try {
                        addInterfaceNum(request, interfaceInfoId, userId);
                    } finally {
                        lock.unlock();
                    }
                }
            });
        }
    }
    
    /**
     * 添加接口num
     * 这段代码是一个私有方法，用于增加接口调用次数和限制接口调用频率。
     * 方法接收三个参数：`ServerHttpRequest request`，`Long interfaceInfoId`，`Long userId`。
     * 首先，通过调用request.getHeaders().getFirst("nonce")方法获取请求头中名为"nonce"的参数值，并将其赋值给变量nonce。
     * 然后，判断nonce是否为空。如果为空，则抛出一个自定义的BusinessException异常，异常的错误码为ErrorCode.FORBIDDEN_ERROR，错误信息为"请求重复"。
     * 这是为了防止重复调用接口。
     * 接下来，调用innerUserInterfaceInfoService.hasLeftNum方法，根据接口信息ID和用户ID查询用户接口信息。
     * 如果返回的userInterfaceInfo为null，则表示接口未绑定用户，需要进行以下操作：
     * 1. 调用innerUserInterfaceInfoService.addDefaultUserInterfaceInfo方法，将接口信息ID和用户ID作为参数，添加默认的用户接口信息。
     * 如果保存失败，则抛出一个自定义的BusinessException异常，异常的错误码为ErrorCode.SYSTEM_ERROR，错误信息为"接口绑定用户失败！"。
     * 如果userInterfaceInfo不为null，表示接口已经绑定了用户，继续进行以下判断：
     * 1. 如果用户接口剩余调用次数小于等于0，则抛出一个自定义的BusinessException异常，异常的错误码为ErrorCode.OPERATION_ERROR，错误信息为"调用次数已用完！"。
     * 接口调用次数和频率限制通过使用Redis的缓存来实现。
     * 首先，调用redisTemplate.opsForValue().set方法，将nonce作为key，1作为value，设置缓存的过期时间为5分钟。
     * 这样可以保证在5分钟内同一个nonce只能调用一次接口。
     * 最后，调用innerUserInterfaceInfoService.invokeCount方法，传入接口信息ID和用户ID，实现接口调用次数 + 1的逻辑。
     * 这段代码的作用是在接口调用时，判断接口的调用次数和频率，并进行相应的限制和处理。
     * @param request         请求
     * @param interfaceInfoId 接口信息id
     * @param userId          用户id
     */
    private void addInterfaceNum(ServerHttpRequest request, Long interfaceInfoId, Long userId) {
        String nonce = request.getHeaders().getFirst("nonce");
        if (StringUtil.isEmpty(nonce)) {
            throw new BusinessException(ErrorCode.FORBIDDEN_ERROR, "请求重复");
        }
        UserInterfaceInfo userInterfaceInfo = innerUserInterfaceInfoService.hasLeftNum(interfaceInfoId, userId);
        // 接口未绑定用户
        if (userInterfaceInfo == null) {
            Boolean save = innerUserInterfaceInfoService.addDefaultUserInterfaceInfo(interfaceInfoId, userId);
            if (save == null || !save) {
                throw new BusinessException(ErrorCode.SYSTEM_ERROR, "接口绑定用户失败！");
            }
        }
        if (userInterfaceInfo != null && userInterfaceInfo.getLeftNum() <= 0) {
            throw new BusinessException(ErrorCode.OPERATION_ERROR, "调用次数已用完！");
        }
        redisTemplate.opsForValue().set(nonce, 1, 5, TimeUnit.MINUTES);
        innerUserInterfaceInfoService.invokeCount(interfaceInfoId, userId);
    }
}
