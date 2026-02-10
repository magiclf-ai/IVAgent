#!/usr/bin/env python3
"""
下载 CDN 资源到本地，解决加载卡顿问题
"""

import os
import urllib.request
import ssl

# 禁用 SSL 验证（某些环境可能需要）
ssl._create_default_https_context = ssl._create_unverified_context

# 静态文件目录
STATIC_DIR = os.path.dirname(os.path.abspath(__file__))

# 需要下载的资源列表
RESOURCES = [
    # highlight.js 主题
    {
        "url": "https://cdn.bootcdn.net/ajax/libs/highlight.js/11.9.0/styles/github.min.css",
        "filename": "highlight-github.min.css"
    },
    # highlight.js 主文件
    {
        "url": "https://cdn.bootcdn.net/ajax/libs/highlight.js/11.9.0/highlight.min.js",
        "filename": "highlight.min.js"
    },
    # highlight.js JSON 语言支持
    {
        "url": "https://cdn.bootcdn.net/ajax/libs/highlight.js/11.9.0/languages/json.min.js",
        "filename": "highlight-json.min.js"
    },
    # Chart.js
    {
        "url": "https://cdn.bootcdn.net/ajax/libs/Chart.js/4.4.1/chart.umd.min.js",
        "filename": "chart.umd.min.js"
    },
]


def download_file(url, filepath):
    """下载文件"""
    print(f"下载: {url}")
    print(f"  -> {filepath}")
    
    try:
        urllib.request.urlretrieve(url, filepath)
        size = os.path.getsize(filepath)
        print(f"  完成 ({size / 1024:.1f} KB)")
        return True
    except Exception as e:
        print(f"  失败: {e}")
        return False


def main():
    print("=" * 60)
    print("下载 CDN 资源到本地")
    print("=" * 60)
    print()
    
    success_count = 0
    failed_count = 0
    
    for resource in RESOURCES:
        filepath = os.path.join(STATIC_DIR, resource["filename"])
        
        if download_file(resource["url"], filepath):
            success_count += 1
        else:
            failed_count += 1
        
        print()
    
    print("=" * 60)
    print(f"下载完成: 成功 {success_count} 个, 失败 {failed_count} 个")
    print("=" * 60)
    
    if failed_count > 0:
        print("\n提示: 如果下载失败，可以手动下载以下文件并放置到 static 目录:")
        for resource in RESOURCES:
            print(f"  - {resource['filename']}")


if __name__ == "__main__":
    main()
