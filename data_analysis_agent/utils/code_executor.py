# -*- coding: utf-8 -*-
"""
安全的代码执行器，基于 IPython 提供 notebook 环境下的代码执行功能
"""

import os
import sys
import ast
import traceback
import io
from typing import Dict, Any, List, Optional, Tuple
from contextlib import redirect_stdout, redirect_stderr
from IPython.core.interactiveshell import InteractiveShell
from IPython.utils.capture import capture_output
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm

class CodeExecutor:
    """
    安全的代码执行器，限制依赖库，捕获输出，支持图片保存与路径输出
    """   
    ALLOWED_IMPORTS = {
        'pandas', 'pd',
        'numpy', 'np', 
        'matplotlib', 'matplotlib.pyplot', 'plt',
        'duckdb', 'scipy', 'sklearn',
        'plotly', 'dash', 'requests', 'urllib',
        'os', 'sys', 'json', 'csv', 'datetime', 'time',
        'math', 'statistics', 're', 'pathlib', 'io',
        'collections', 'itertools', 'functools', 'operator',
        'warnings', 'logging', 'copy', 'pickle', 'gzip', 'zipfile',
        'typing', 'dataclasses', 'enum', 'sqlite3'
    }
    
    def __init__(self, output_dir: str = "outputs"):
        """
        初始化代码执行器
        
        Args:
            output_dir: 输出目录，用于保存图片和文件
        """
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 初始化 IPython shell
        # 初始化并获取 IPython 交互式 shell 的单例实例，以便在程序中嵌入 IPython 的交互式功能（如执行代码、处理输入输出、支持魔法命令等）
        self.shell = InteractiveShell.instance()
        
        # 设置中文字体
        self._setup_chinese_font()
        
        # 预导入常用库
        self._setup_common_imports()
        
        # 图片计数器
        self.image_counter = 0
        
    def _setup_chinese_font(self):
        """设置matplotlib中文字体显示"""
        try:
            # 设置matplotlib使用Agg backend避免GUI问题
            matplotlib.use('Agg')
            
            # 设置matplotlib使用simhei字体显示中文
            plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans', 'Arial Unicode MS']
            plt.rcParams['axes.unicode_minus'] = False
              # 在shell中也设置
            self.shell.run_cell("""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans', 'Arial Unicode MS']
plt.rcParams['axes.unicode_minus'] = False
""")
        except Exception as e:
            print(f"设置中文字体失败: {e}")
            
    def _setup_common_imports(self):
        """预导入常用库"""
        common_imports = """
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import duckdb
import os
import json
from IPython.display import display
"""
        try:
            self.shell.run_cell(common_imports)
            # 确保display函数在shell的用户命名空间中可用
            from IPython.display import display
            self.shell.user_ns['display'] = display
        except Exception as e:
            print(f"预导入库失败: {e}")
    
    def _check_code_safety(self, code: str) -> Tuple[bool, str]:
        """
        检查代码安全性，限制导入的库和危险函数调用，防止执行恶意代码或不安全操作
        
        Returns:
            (is_safe, error_message): 元组，第一个元素为布尔值（True表示安全，False表示不安全），
                                    第二个元素为错误信息（安全时为空字符串，不安全时说明具体原因）
        """
        try:
            # 将输入的代码字符串解析为抽象语法树（AST），用于后续分析代码结构
            # AST是代码的结构化表示，可通过遍历节点判断代码是否包含危险操作
            tree = ast.parse(code)
        except SyntaxError as e:
            # 如果代码存在语法错误（如拼写错误、语法不完整），直接返回不安全及错误信息
            return False, f"语法错误: {e}"
        
        # 遍历AST中的所有节点（递归访问所有子节点），检查是否存在不安全操作
        for node in ast.walk(tree):
            # 1. 检查"直接导入"语句（如 import os, import requests）
            if isinstance(node, ast.Import):
                # 遍历导入的每个库别名（如 import os as o 中的 'os'）
                for alias in node.names:
                    # 如果导入的库不在允许的列表（self.ALLOWED_IMPORTS）中，判定为不安全
                    if alias.name not in self.ALLOWED_IMPORTS:
                        return False, f"不允许的导入: {alias.name}"
            
            # 2. 检查"从模块导入"语句（如 from os import path, from subprocess import call）
            elif isinstance(node, ast.ImportFrom):
                # 检查导入的模块名（如 from os import ... 中的 'os'）是否在允许列表中
                if node.module not in self.ALLOWED_IMPORTS:
                    return False, f"不允许的导入: {node.module}"
            
            # 3. 检查危险函数调用（可能执行任意代码或绕过限制的函数）
            elif isinstance(node, ast.Call):
                # 判断函数调用的是否是直接通过名称调用的函数（如 exec("code") 中的 'exec'）
                if isinstance(node.func, ast.Name):
                    # 禁止调用 exec（执行字符串为代码）、eval（计算表达式为代码）、__import__（动态导入模块）
                    # 这些函数可能被用于执行未授权操作或导入危险库
                    if node.func.id in ['exec', 'eval', '__import__']:
                        return False, f"不允许的函数调用: {node.func.id}"
        
        # 所有节点检查通过，代码安全
        return True, ""
    
    def get_current_figures_info(self) -> List[Dict[str, Any]]:
        """获取当前matplotlib图形信息，但不自动保存"""
        figures_info = []
        
        # 获取当前所有图形
        fig_nums = plt.get_fignums()
        
        for fig_num in fig_nums:
            fig = plt.figure(fig_num)
            if fig.get_axes():  # 只处理有内容的图形
                figures_info.append({
                    'figure_number': fig_num,
                    'axes_count': len(fig.get_axes()),
                    'figure_size': fig.get_size_inches().tolist(),
                    'has_content': True
                })
        
        return figures_info
    
    def _format_table_output(self, obj: Any) -> str:
        """格式化表格输出，限制行数"""
        if hasattr(obj, 'shape') and hasattr(obj, 'head'):  # pandas DataFrame
            rows, cols = obj.shape
            print(f"\n数据表形状: {rows}行 x {cols}列")
            print(f"列名: {list(obj.columns)}")
            
            if rows <= 15:
                return str(obj)
            else:
                head_part = obj.head(5)
                tail_part = obj.tail(5)
                return f"{head_part}\n...\n(省略 {rows-10} 行)\n...\n{tail_part}"
        
        return str(obj)
    
    def execute_code(self, code: str) -> Dict[str, Any]:
        """
        执行代码并返回结果
        
        Args:
            code: 要执行的Python代码
            
        Returns:
            {
                'success': bool,
                'output': str,
                'error': str,
                'variables': Dict[str, Any]  # 新生成的重要变量
            }
        """
        # 检查代码安全性
        is_safe, safety_error = self._check_code_safety(code)
        if not is_safe:
            return {
                'success': False,
                'output': '',
                'error': f"代码安全检查失败: {safety_error}",
                'variables': {}
            }
        
        # 记录执行前的变量
        vars_before = set(self.shell.user_ns.keys())
        
        try:
            # 使用IPython的capture_output来捕获所有输出
            with capture_output() as captured:
                result = self.shell.run_cell(code)
            
            # 检查执行结果
            if result.error_before_exec:
                error_msg = str(result.error_before_exec)
                return {
                    'success': False,
                    'output': captured.stdout,
                    'error': f"执行前错误: {error_msg}",
                    'variables': {}
                }
            
            if result.error_in_exec:
                error_msg = str(result.error_in_exec)
                return {
                    'success': False,
                    'output': captured.stdout,
                    'error': f"执行错误: {error_msg}",
                    'variables': {}
                }
            
            # 获取输出
            output = captured.stdout
            
            # 如果有返回值，添加到输出
            if result.result is not None:
                formatted_result = self._format_table_output(result.result)
                output += f"\n{formatted_result}"
              # 记录新产生的重要变量（简化版本）
            vars_after = set(self.shell.user_ns.keys())
            new_vars = vars_after - vars_before
            
            # 只记录新创建的DataFrame等重要数据结构
            important_new_vars = {}
            for var_name in new_vars:
                if not var_name.startswith('_'):
                    try:
                        var_value = self.shell.user_ns[var_name]
                        if hasattr(var_value, 'shape'):  # pandas DataFrame, numpy array
                            important_new_vars[var_name] = f"{type(var_value).__name__} with shape {var_value.shape}"
                        elif var_name in ['session_output_dir']:  # 重要的配置变量
                            important_new_vars[var_name] = str(var_value)
                    except:
                        pass
            
            return {
                'success': True,
                'output': output,                'error': '',
                'variables': important_new_vars
            }
        except Exception as e:
            return {
                'success': False,
                'output': captured.stdout if 'captured' in locals() else '',
                'error': f"执行异常: {str(e)}\n{traceback.format_exc()}",
                'variables': {}
            }    
    
    def reset_environment(self):
        """重置执行环境"""
        self.shell.reset()
        self._setup_common_imports()
        self._setup_chinese_font()
        plt.close('all')
        self.image_counter = 0
    
    def set_variable(self, name: str, value: Any):
        """设置执行环境中的变量"""
        self.shell.user_ns[name] = value
    
    def get_environment_info(self) -> str:
        """获取当前执行环境的变量信息，用于系统提示词
        功能：收集用户当前交互环境中的关键变量（如数据结构、路径、导入的库等），
            整理成结构化文本，帮助系统提示词了解当前环境状态，辅助后续操作（如代码生成、数据处理）
        返回：包含环境变量信息的字符串
        """
        # 用于存储环境信息的片段，最后拼接成完整字符串
        info_parts = []
        
        # 存储需要收集的重要变量信息（键：变量名，值：变量的简化描述）
        important_vars = {}
        
        # 遍历IPython shell的用户命名空间（self.shell.user_ns包含用户定义的所有变量）
        for var_name, var_value in self.shell.user_ns.items():
            # 过滤条件：
            # 1. 排除以下划线开头的变量（通常是临时变量或内部变量）
            # 2. 排除IPython内置变量（如In/Out是输入输出历史，get_ipython等是shell工具）
            if not var_name.startswith('_') and var_name not in ['In', 'Out', 'get_ipython', 'exit', 'quit']:
                try:
                    # 处理有shape属性的变量（如pandas DataFrame、numpy数组等数据结构）
                    if hasattr(var_value, 'shape'):
                        # 记录变量类型（如DataFrame、ndarray）和形状（如(100,5)表示100行5列）
                        important_vars[var_name] = f"{type(var_value).__name__} with shape {var_value.shape}"
                    
                    # 特殊处理重要的路径变量（如session_output_dir，通常用于存储输出文件）
                    elif var_name in ['session_output_dir']:
                        important_vars[var_name] = str(var_value)  # 直接记录路径字符串
                    
                    # 处理基本数据类型（int/float/str/bool）且值较短的变量（避免过长文本占用空间）
                    elif isinstance(var_value, (int, float, str, bool)) and len(str(var_value)) < 100:
                        important_vars[var_name] = f"{type(var_value).__name__}: {var_value}"  # 记录类型和值
                    
                    # 处理特定库的导入对象（如pandas/numpy/matplotlib的模块或实例）
                    elif hasattr(var_value, '__module__') and var_value.__module__ in ['pandas', 'numpy', 'matplotlib.pyplot']:
                        important_vars[var_name] = f"导入的模块: {var_value.__module__}"  # 记录所属模块
                
                # 捕获变量处理中的异常（如某些对象的shape属性访问可能报错），跳过当前变量
                except:
                    continue
        
        # 如果收集到重要变量，将其格式化添加到信息片段
        if important_vars:
            info_parts.append("当前环境变量:")  # 添加标题
            # 遍历变量，按格式添加到列表（如"- 变量名: 描述"）
            for var_name, var_info in important_vars.items():
                info_parts.append(f"- {var_name}: {var_info}")
        # 如果没有重要变量，说明环境中可能只有预装库
        else:
            info_parts.append("当前环境已预装pandas, numpy, matplotlib等库")
        
        # 单独补充输出目录信息（如果存在），方便系统知道图片等文件的保存路径
        if 'session_output_dir' in self.shell.user_ns:
            info_parts.append(f"图片保存目录: session_output_dir = '{self.shell.user_ns['session_output_dir']}'")
        
        # 将所有信息片段用换行符拼接成完整字符串并返回
        return "\n".join(info_parts)
