"""Pipeline execution engine — modular block-based automation for PurpleLab."""
from backend.agent.pipeline.executor import PipelineExecutor, PipelineError
from backend.agent.pipeline.blocks import BLOCK_REGISTRY, get_block

__all__ = ["PipelineExecutor", "PipelineError", "BLOCK_REGISTRY", "get_block"]
