"""
数据加载工具模块
"""

import pandas as pd
from pathlib import Path
from typing import Optional, Union

def load_csv_data(
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    **kwargs
) -> pd.DataFrame:
    """
    加载 CSV 文件

    Parameters:
    -----------
    file_path : Union[str, Path]
        文件路径
    encoding : str
        文件编码，默认为 utf-8
    **kwargs
        传递给 pd.read_csv 的其他参数

    Returns:
    --------
    pd.DataFrame
        加载的数据框
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")

    df = pd.read_csv(file_path, encoding=encoding, **kwargs)
    print(f" 成功加载数据: {file_path}")
    print(f"   数据形状: {df.shape}")
    print(f"   列名: {list(df.columns)}")

    return df

def load_json_data(
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    **kwargs
) -> pd.DataFrame:
    """
    加载 JSON 文件

    Parameters:
    -----------
    file_path : Union[str, Path]
        文件路径
    encoding : str
        文件编码，默认为 utf-8
    **kwargs
        传递给 pd.read_json 的其他参数

    Returns:
    --------
    pd.DataFrame
        加载的数据框
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")

    df = pd.read_json(file_path, encoding=encoding, **kwargs)
    print(f" 成功加载数据: {file_path}")
    print(f"   数据形状: {df.shape}")
    print(f"   列名: {list(df.columns)}")

    return df

def save_data(
    df: pd.DataFrame,
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    index: bool = False,
    **kwargs
) -> None:
    """
    保存数据到文件

    Parameters:
    -----------
    df : pd.DataFrame
        要保存的数据框
    file_path : Union[str, Path]
        文件路径
    encoding : str
        文件编码，默认为 utf-8
    index : bool
        是否保存索引，默认为 False
    **kwargs
        传递给保存函数的其他参数
    """
    file_path = Path(file_path)
    # 确保目录存在
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # 根据文件扩展名选择保存方法
    if file_path.suffix == '.csv':
        df.to_csv(file_path, encoding=encoding, index=index, **kwargs)
    elif file_path.suffix == '.json':
        df.to_json(file_path, encoding=encoding, force_ascii=False, **kwargs)
    elif file_path.suffix == '.parquet':
        df.to_parquet(file_path, **kwargs)
    else:
        raise ValueError(f"不支持的文件格式: {file_path.suffix}")

    print(f" 数据已保存: {file_path}")
