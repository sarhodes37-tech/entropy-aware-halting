"""
EpistemicOS Hardware Telemetry & Profiling Module.
Tracks true CUDA/MPS latency, VRAM allocation, and KV-cache fragmentation
to quantify the overhead of entropy extraction and dynamic rollbacks.
"""

import time
import logging
import torch
from dataclasses import dataclass
from typing import Dict, Any, Optional

logger = logging.getLogger("EpistemicOS.Profiler")

@dataclass
class HardwareTelemetry:
    wall_clock_ms: float
    cuda_time_ms: float
    vram_allocated_mb: float
    vram_reserved_mb: float
    vram_peak_mb: float
    fragmentation_index: float  # (Reserved - Allocated) / Reserved
    tokens_processed: int
    ms_per_token: float

class ResourceProfiler:
    """
    Context manager for high-precision hardware profiling.
    Safely degrades to standard time.perf_counter() if running on CPU.
    """
    
    def __init__(self, device: str = "cuda", token_count: int = 0):
        self.device = device
        self.token_count = max(1, token_count)
        self.use_cuda = "cuda" in self.device and torch.cuda.is_available()
        
        if self.use_cuda:
            self.start_event = torch.cuda.Event(enable_timing=True)
            self.end_event = torch.cuda.Event(enable_timing=True)

    def __enter__(self):
        self.start_wall = time.perf_counter()
        
        if self.use_cuda:
            torch.cuda.reset_peak_memory_stats()
            self.start_event.record()
            
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.use_cuda:
            self.end_event.record()
            torch.cuda.synchronize() # Wait for GPU to finish execution
            self.cuda_time_ms = self.start_event.elapsed_time(self.end_event)
        else:
            self.cuda_time_ms = 0.0

        self.end_wall = time.perf_counter()
        self.wall_clock_ms = (self.end_wall - self.start_wall) * 1000.0

    def get_telemetry(self) -> HardwareTelemetry:
        """Calculates and returns memory and latency telemetry."""
        alloc_mb = 0.0
        res_mb = 0.0
        peak_mb = 0.0
        frag_index = 0.0
        
        if self.use_cuda:
            alloc_mb = torch.cuda.memory_allocated() / (1024 ** 2)
            res_mb = torch.cuda.memory_reserved() / (1024 ** 2)
            peak_mb = torch.cuda.max_memory_allocated() / (1024 ** 2)
            
            # High fragmentation (> 0.3) indicates KV-cache is physically scattered 
            # and highly vulnerable to OOM during dynamic rollbacks
            if res_mb > 0:
                frag_index = (res_mb - alloc_mb) / res_mb

        # Default to wall clock if CUDA timing isn't available
        effective_time = self.cuda_time_ms if self.use_cuda else self.wall_clock_ms

        return HardwareTelemetry(
            wall_clock_ms=round(self.wall_clock_ms, 2),
            cuda_time_ms=round(self.cuda_time_ms, 2),
            vram_allocated_mb=round(alloc_mb, 2),
            vram_reserved_mb=round(res_mb, 2),
            vram_peak_mb=round(peak_mb, 2),
            fragmentation_index=round(frag_index, 4),
            tokens_processed=self.token_count,
            ms_per_token=round(effective_time / self.token_count, 2)
        )
