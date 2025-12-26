# filters.py

from django_filters import rest_framework as filters
from .models import ActionLog
from django.db.models import Q

# 動態導入以避免循環導入
try:
    from clinic.models import ClinicUserPermission
except ImportError:  # pragma: no cover
    ClinicUserPermission = None  # type: ignore[assignment,misc]


class ActionLogFilter(filters.FilterSet):
    # Define the filters
    # model_name 用於格式 "ModelName:object_id" 的查詢，或單獨使用 "ModelName"
    model_name = filters.CharFilter(
        method="filter_by_model_name_object_id", required=False
    )
    # 獨立的 model_name 過濾器，用於單獨使用
    model_name_only = filters.CharFilter(
        field_name="model_name", lookup_expr="exact", required=False
    )
    # object_id 過濾器，但只在與 model_name_only 組合使用時才生效
    object_id = filters.CharFilter(
        field_name="object_id", lookup_expr="exact", required=False
    )

    class Meta:
        model = ActionLog
        fields = [
            "user",
            "action",
            "model_name",
            "model_name_only",
            "object_id",
            "timestamp",
            "changes",
        ]

    def filter_by_model_name_object_id(self, queryset, name, value):
        """
        處理格式為 "ModelName:object_id" 的查詢參數
        例如: model_name=Clinic:1 或 model_name=Clinic:1,User:2

        如果格式不正確（沒有冒號），只匹配 model_name
        """
        if not value:
            return queryset

        pairs = value.split(",")
        conditions = Q()

        for pair in pairs:
            pair = pair.strip()  # 去除空格
            if not pair:
                continue

            try:
                model_name, object_id = pair.split(":", 1)  # 只分割第一個冒號
                model_name = model_name.strip()
                object_id = object_id.strip()

                # Handle the special case for 'ClinicUserPermission'
                # 當 object_id 是 user_id 時，需要找到所有包含該 user 的 ClinicUserPermission 記錄
                # 注意：由於 ClinicUserPermission 可能通過 UserViewSet 的 clinic_ids 欄位更新，
                # 變更記錄可能在 User 模型中，而不是 ClinicUserPermission 模型中
                if (
                    model_name == "ClinicUserPermission"
                    and ClinicUserPermission is not None
                ):
                    try:
                        user_id = int(object_id)
                        user_id_str = str(user_id)

                        # 找到所有 user_id 等於該值的 ClinicUserPermission 實例
                        permission_ids = list(
                            ClinicUserPermission.objects.filter(
                                user_id=user_id
                            ).values_list("id", flat=True)
                        )

                        # 將這些 ID 轉換為字符串列表（因為 object_id 是 CharField）
                        permission_id_strings = [str(pid) for pid in permission_ids]

                        # 構建查詢條件
                        clinic_permission_conditions = Q()

                        # 1. 直接匹配 ClinicUserPermission 的 object_id（如果 ActionLog 中有記錄）
                        if permission_id_strings:
                            clinic_permission_conditions |= Q(
                                model_name=model_name,
                                object_id__in=permission_id_strings,
                            )

                        # 2. 檢查 ClinicUserPermission 的 changes 欄位中是否包含該 user_id
                        clinic_permission_conditions |= Q(
                            model_name=model_name, changes__icontains=user_id_str
                        )

                        # 3. 查找 User 模型的變更記錄，特別是包含 clinic_ids 變更的記錄
                        # 因為當通過 UserViewSet 更新 clinic_ids 時，變更記錄在 User 模型中
                        clinic_permission_conditions |= Q(
                            model_name="User",
                            object_id=user_id_str,
                            changes__icontains="clinic_ids",
                        )

                        # 將條件添加到主條件中（使用 OR 連接）
                        conditions |= clinic_permission_conditions
                    except (ValueError, TypeError):
                        # 如果 object_id 不是有效的整數，回退到原來的邏輯
                        conditions |= Q(
                            model_name=model_name, changes__icontains=object_id
                        )
                else:
                    # 對於其他模型，直接匹配 model_name 和 object_id
                    conditions |= Q(model_name=model_name, object_id=object_id)

            except ValueError:
                # If the format is invalid (沒有冒號)，只匹配 model_name
                # 這樣可以支持 model_name=Clinic 這種單獨使用的情況
                conditions |= Q(model_name=pair.strip())

        return queryset.filter(conditions)
