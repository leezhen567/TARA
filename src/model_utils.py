"""
模型工具模块
"""

import torch
from transformers import (
    AutoTokenizer, 
    AutoModel, 
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer
)
from pathlib import Path
from typing import Optional, Union, Dict, Any

def load_tokenizer(
    model_name_or_path: Union[str, Path],
    **kwargs
) -> AutoTokenizer:
    """
    加载 Tokenizer

    Parameters:
    -----------
    model_name_or_path : Union[str, Path]
        模型名称或路径
    **kwargs
        传递给 AutoTokenizer.from_pretrained 的其他参数

    Returns:
    --------
    AutoTokenizer
        加载的 tokenizer
    """
    tokenizer = AutoTokenizer.from_pretrained(model_name_or_path, **kwargs)
    print(f" 成功加载 Tokenizer: {model_name_or_path}")
    return tokenizer

def load_model(
    model_name_or_path: Union[str, Path],
    model_type: str = 'auto',
    **kwargs
) -> Union[AutoModel, AutoModelForSequenceClassification]:
    """
    加载模型

    Parameters:
    -----------
    model_name_or_path : Union[str, Path]
        模型名称或路径
    model_type : str
        模型类型: 'auto', 'sequence_classification', 'causal_lm', 等
    **kwargs
        传递给模型加载函数的其他参数

    Returns:
    --------
    model
        加载的模型
    """
    model_name_or_path = str(model_name_or_path)

    if model_type == 'sequence_classification':
        model = AutoModelForSequenceClassification.from_pretrained(
            model_name_or_path, **kwargs
        )
    elif model_type == 'auto':
        model = AutoModel.from_pretrained(model_name_or_path, **kwargs)
    else:
        raise ValueError(f"不支持的模型类型: {model_type}")

    # 打印模型信息
    print(f" 成功加载模型: {model_name_or_path}")
    print(f"   模型类型: {type(model).__name__}")
    print(f"   参数数量: {model.num_parameters():,}")

    if torch.cuda.is_available():
        print(f"   设备: CUDA (GPU)")
    else:
        print(f"   设备: CPU")

    return model

def save_model(
    model,
    tokenizer,
    save_path: Union[str, Path],
    **kwargs
) -> None:
    """
    保存模型和 tokenizer

    Parameters:
    -----------
    model
        要保存的模型
    tokenizer
        要保存的 tokenizer
    save_path : Union[str, Path]
        保存路径
    **kwargs
        传递给保存函数的其他参数
    """
    save_path = Path(save_path)
    # 确保目录存在
    save_path.mkdir(parents=True, exist_ok=True)

    # 保存模型
    model.save_pretrained(save_path, **kwargs)
    # 保存 tokenizer
    tokenizer.save_pretrained(save_path, **kwargs)

    print(f" 模型和 Tokenizer 已保存: {save_path}")

def get_training_args(
    output_dir: Union[str, Path],
    num_train_epochs: int = 3,
    per_device_train_batch_size: int = 16,
    per_device_eval_batch_size: int = 16,
    learning_rate: float = 5e-5,
    warmup_steps: int = 500,
    weight_decay: float = 0.01,
    logging_dir: Optional[Union[str, Path]] = None,
    evaluation_strategy: str = "epoch",
    save_strategy: str = "epoch",
    load_best_model_at_end: bool = True,
    **kwargs
) -> TrainingArguments:
    """
    获取训练参数

    Parameters:
    -----------
    output_dir : Union[str, Path]
        输出目录
    num_train_epochs : int
        训练轮数，默认为 3
    per_device_train_batch_size : int
        每设备训练批量大小，默认为 16
    per_device_eval_batch_size : int
        每设备评估批量大小，默认为 16
    learning_rate : float
        学习率，默认为 5e-5
    warmup_steps : int
        预热步数，默认为 500
    weight_decay : float
        权重衰减，默认为 0.01
    logging_dir : Optional[Union[str, Path]]
        日志目录
    evaluation_strategy : str
        评估策略，默认为 "epoch"
    save_strategy : str
        保存策略，默认为 "epoch"
    load_best_model_at_end : bool
        是否在结束时加载最佳模型，默认为 True
    **kwargs
        传递给 TrainingArguments 的其他参数

    Returns:
    --------
    TrainingArguments
        训练参数对象
    """
    if logging_dir is None:
        logging_dir = str(output_dir) + "/logs"

    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=num_train_epochs,
        per_device_train_batch_size=per_device_train_batch_size,
        per_device_eval_batch_size=per_device_eval_batch_size,
        learning_rate=learning_rate,
        warmup_steps=warmup_steps,
        weight_decay=weight_decay,
        logging_dir=logging_dir,
        evaluation_strategy=evaluation_strategy,
        save_strategy=save_strategy,
        load_best_model_at_end=load_best_model_at_end,
        **kwargs
    )

    return training_args
