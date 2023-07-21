package cn.ichensw.neroapiinterface.interceptor;

import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 染色数据拦截器
 *
 * 该拦截器的作用是在请求进入Controller方法之前，对请求的染色数据进行验证。
 * 如果染色数据不符合要求，则返回一个403 Forbidden的错误响应，否则允许请求继续向下执行。
 * @author 嘻精
 * @date 2023/07/21
 */
public class DyeDataInterceptor implements HandlerInterceptor {

    private static final String DYE_DATA_HEADER = "X-Dye-Data";
    private static final String DYE_DATA_VALUE = "nero";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 获取请求头中的染色数据
        String dyeData = request.getHeader(DYE_DATA_HEADER);

        if (dyeData == null || !dyeData.equals(DYE_DATA_VALUE)) {
            // 如果染色数据不存在或者不匹配，则返回错误响应
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }

        // 继续向下执行
        return true;
    }
}
