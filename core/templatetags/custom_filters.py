from django import template

register = template.Library()

@register.filter
def filter_by_attribute(queryset, filter_string):
    """
    Filter queryset by attribute:value pair
    Usage: {{ my_queryset|filter_by_attribute:"attribute:value" }}
    """
    try:
        attr, value = filter_string.split(':')
        kwargs = {attr: value == 'True'}
        return [obj for obj in queryset if getattr(obj, attr) == kwargs[attr]]
    except (ValueError, AttributeError):
        return queryset