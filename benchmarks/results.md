# DinoScan - Local Model Benchmarks
# Generated: 2026-02-15

## Benchmark Summary

| Model | Base | TPS | Load Time | Total Time | Tokens |
|-------|------|-----|-----------|------------|--------|
| rex-dino | phi3:mini | 5.02 tok/s | 32.6s | 2m44s | 615 |
| rex-dino-qwen3 | qwen3:8b | 4.85 tok/s | 48s | 2m46s | 523 |
| rex-dino-qwen3:4b | qwen3:4b | 2.41 tok/s | 53.5s | 23m12s | 3090 |

## Details

### Test Command
```bash
ollama run [model] "Write a 200-word story about robots" --verbose
```

### rex-dino (phi3:mini) - BEST
- **Date**: 2026-02-14
- **Model**: rex-dino:latest (phi3:mini base)
- **TPS**: 5.02 tokens/second
- **Load Duration**: 32.620 seconds
- **Total Duration**: 2m44.23s
- **Prompt Eval Rate**: 7.07 tokens/s
- **Eval Count**: 615 tokens

### rex-dino-qwen3 (qwen3:8b)
- **Date**: 2026-02-14
- **Model**: rex-dino-qwen3:latest (qwen3:8b base)
- **TPS**: 4.85 tokens/second
- **Load Duration**: 48.09 seconds
- **Total Duration**: 2m46.35s
- **Prompt Eval Rate**: 6.74 tokens/s
- **Eval Count**: 523 tokens

### rex-dino-qwen3:4b (qwen3:4b) - SLOWEST
- **Date**: 2026-02-15
- **Model**: rex-dino-qwen3:4b (qwen3:4b base)
- **TPS**: 2.41 tokens/second
- **Load Duration**: 53.46 seconds
- **Total Duration**: 23m12.14s
- **Prompt Eval Rate**: 6.24 tokens/s
- **Eval Count**: 3090 tokens

## Conclusions

1. **phi3:mini is the fastest** on CPU - 5 TPS
2. **qwen3:8b is slightly slower** - 4.85 TPS but longer load time
3. **qwen3:4b is TOO SLOW** - only 2.4 TPS!

## Recommendation

**Use phi3:mini (rex-dino)** for CPU inference. It's:
- Fastest (5 TPS)
- Smallest (2.2 GB)
- Best performance on consumer hardware

For faster inference, consider:
- Adding a GPU (RTX 3060+)
- Using quantized models (Q4_K_M)
- Running vLLM instead of Ollama
