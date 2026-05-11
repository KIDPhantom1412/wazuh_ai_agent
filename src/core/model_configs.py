def get_model_kwargs(model_name: str) -> dict:
    """
    根据模型名称动态返回专属的 kwargs 配置
    """
    model_name_lower = model_name.lower()
    kwargs = {}

    # 针对 DeepSeek Pro模型：禁用思考模式
    if "deepseek" in model_name_lower and "pro" in model_name_lower:
        kwargs["extra_body"] = {"thinking": {"type": "disabled"}}

    return kwargs if kwargs else None
