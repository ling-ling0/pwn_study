def analyze_final_states():
    """分析最终状态的分布"""
    
    final_values = {}
    
    for start in range(1, 101):
        seed = start
        # 执行120次change
        for _ in range(120):
            if seed & 1:
                seed = 3 * seed + 1
            else:
                seed = seed >> 1
        
        # 确保是奇数
        while not (seed & 1):
            seed = seed >> 1
        
        if seed not in final_values:
            final_values[seed] = []
        final_values[seed].append(start)
    
    print("最终状态分布:")
    for final_val, initial_vals in final_values.items():
        print(f"最终值 {final_val:8d} <- 来自初始值: {initial_vals}")
    
    return final_values

final_distribution = analyze_final_states()