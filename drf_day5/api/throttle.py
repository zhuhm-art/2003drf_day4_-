from rest_framework.throttling import SimpleRateThrottle


class SendMessageRate(SimpleRateThrottle):
    scope = "send"

    # 只对含有手机号的请求做验证
    def get_cache_key(self, request, view):
        phone = request.query_params.get("phone")

        # 没有手机号不做限制
        if not phone:
            return None

        # 返回数据  根据手机号动态展示返回的值
        return 'throttle_%(scope)s_%(ident)s' % {"scope": self.scope, "ident": phone}
