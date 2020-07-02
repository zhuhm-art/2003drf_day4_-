from rest_framework.permissions import BasePermission

from api.models import User


class MyPermission(BasePermission):
    """
    有权限访问返回True
    无权限访问返回False
    登录可写  游客只读
    """

    def has_permission(self, request, view):
        # 如果是只读接口  则所有人都可以访问
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return True

        username = request.data.get("username")
        # 如果用户访问的是写操作  判断用户是否有登录信息
        user = User.objects.filter(username=username).first()
        print(user)

        if user:
            return True
        return False
