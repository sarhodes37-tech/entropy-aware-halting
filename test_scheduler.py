import torch
from scheduler import EntropyAwareScheduler

scheduler = EntropyAwareScheduler()
scheduler.step(torch.tensor([0.5, 0.5]), cost=0, state=None)
scheduler.step(torch.tensor([0.9, 0.1]), cost=0, state=None)
