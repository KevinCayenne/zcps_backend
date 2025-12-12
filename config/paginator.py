from django.db.models import sql
from django.utils.functional import cached_property
from django.core.paginator import Paginator as DjangoPaginator
from rest_framework.pagination import PageNumberPagination


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 1000


class RawQuerySetPaginator(DjangoPaginator):
    @cached_property
    def count(self):
        copy_query_set = self.object_list._clone()
        count_raw_query = f"""
        SELECT COUNT('id') AS id FROM ({copy_query_set.raw_query}) AS subquery
        """
        copy_query_set.query = sql.RawQuery(
            sql=count_raw_query, using=copy_query_set.db, params=copy_query_set.params
        )
        if copy_query_set._result_cache is None:
            copy_query_set._fetch_all()
        return copy_query_set._result_cache[0].id or 0

    def page(self, number):
        """Return a Page object for the given 1-based page number."""
        number = self.validate_number(number)
        bottom = (number - 1) * self.per_page

        copy_query_set = self.object_list._clone()
        slice_raw_query = f"""
        {copy_query_set.raw_query}
        LIMIT {self.per_page} OFFSET {bottom}
        """
        copy_query_set.query = sql.RawQuery(
            sql=slice_raw_query, using=copy_query_set.db, params=copy_query_set.params
        )
        return self._get_page(list(copy_query_set), number, self)


class RawQuerySetResultsPagination(StandardResultsSetPagination):
    django_paginator_class = RawQuerySetPaginator
