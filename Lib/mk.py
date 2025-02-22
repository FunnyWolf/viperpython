def list_to_markdown(list_str: list):
    markdown_list = "\n- ".join(list_str)

    # 添加开始的 '- ' 以符合Markdown列表的格式
    markdown_string = "- " + markdown_list
    return markdown_string
